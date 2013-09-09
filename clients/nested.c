/*
 * Copyright © 2013 Intel Corporation
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting documentation, and
 * that the name of the copyright holders not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  The copyright holders make no representations
 * about the suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cairo.h>
#include <math.h>
#include <assert.h>
#include <pixman.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>

#include <cairo-gl.h>

#include <wayland-client.h>
#define WL_HIDE_DEPRECATED
#include <wayland-server.h>

#include "window.h"

#define MIN(x,y) (((x) < (y)) ? (x) : (y))

struct nested {
	struct display *display;
	struct window *window;
	struct widget *widget;
	struct wl_display *child_display;
	struct task child_task;

	EGLDisplay egl_display;
	struct program *texture_program;

	struct wl_list surface_list;
};

struct nested_region {
	struct wl_resource *resource;
	pixman_region32_t region;
};

struct nested_buffer {
	struct wl_resource *resource;
	struct wl_signal destroy_signal;
	struct wl_listener destroy_listener;
	uint32_t busy_count;
};

struct nested_buffer_reference {
	struct nested_buffer *buffer;
	struct wl_listener destroy_listener;
};

struct nested_surface {
	struct wl_resource *resource;
	struct nested_buffer_reference buffer_ref;
	struct nested *nested;
	EGLImageKHR *image;
	GLuint texture;
	struct wl_list link;
	cairo_surface_t *cairo_surface;

	struct wl_list frame_callback_list;

	struct {
		/* wl_surface.attach */
		int newly_attached;
		struct nested_buffer *buffer;
		struct wl_listener buffer_destroy_listener;

		/* wl_surface.frame */
		struct wl_list frame_callback_list;

		/* wl_surface.damage */
		pixman_region32_t damage;
	} pending;
};

struct nested_frame_callback {
	struct wl_resource *resource;
	struct wl_list link;
};

static PFNGLEGLIMAGETARGETTEXTURE2DOESPROC image_target_texture_2d;
static PFNEGLCREATEIMAGEKHRPROC create_image;
static PFNEGLDESTROYIMAGEKHRPROC destroy_image;
static PFNEGLBINDWAYLANDDISPLAYWL bind_display;
static PFNEGLUNBINDWAYLANDDISPLAYWL unbind_display;
static PFNEGLQUERYWAYLANDBUFFERWL query_buffer;

static void
nested_buffer_destroy_handler(struct wl_listener *listener, void *data)
{
	struct nested_buffer *buffer =
		container_of(listener, struct nested_buffer, destroy_listener);

	wl_signal_emit(&buffer->destroy_signal, buffer);
	free(buffer);
}

static struct nested_buffer *
nested_buffer_from_resource(struct wl_resource *resource)
{
	struct nested_buffer *buffer;
	struct wl_listener *listener;

	listener =
		wl_resource_get_destroy_listener(resource,
						 nested_buffer_destroy_handler);

	if (listener)
		return container_of(listener, struct nested_buffer,
				    destroy_listener);

	buffer = zalloc(sizeof *buffer);
	if (buffer == NULL)
		return NULL;

	buffer->resource = resource;
	wl_signal_init(&buffer->destroy_signal);
	buffer->destroy_listener.notify = nested_buffer_destroy_handler;
	wl_resource_add_destroy_listener(resource, &buffer->destroy_listener);

	return buffer;
}

static void
nested_buffer_reference_handle_destroy(struct wl_listener *listener,
				       void *data)
{
	struct nested_buffer_reference *ref =
		container_of(listener, struct nested_buffer_reference,
			     destroy_listener);

	assert((struct nested_buffer *)data == ref->buffer);
	ref->buffer = NULL;
}

static void
nested_buffer_reference(struct nested_buffer_reference *ref,
			struct nested_buffer *buffer)
{
	if (buffer == ref->buffer)
		return;

	if (ref->buffer) {
		ref->buffer->busy_count--;
		if (ref->buffer->busy_count == 0) {
			assert(wl_resource_get_client(ref->buffer->resource));
			wl_resource_queue_event(ref->buffer->resource,
						WL_BUFFER_RELEASE);
		}
		wl_list_remove(&ref->destroy_listener.link);
	}

	if (buffer) {
		buffer->busy_count++;
		wl_signal_add(&buffer->destroy_signal,
			      &ref->destroy_listener);

		ref->destroy_listener.notify =
			nested_buffer_reference_handle_destroy;
	}

	ref->buffer = buffer;
}

static void
flush_surface_frame_callback_list(struct nested_surface *surface,
				  uint32_t time)
{
	struct nested_frame_callback *nc, *next;

	wl_list_for_each_safe(nc, next, &surface->frame_callback_list, link) {
		wl_callback_send_done(nc->resource, time);
		wl_resource_destroy(nc->resource);
	}
	wl_list_init(&surface->frame_callback_list);

	/* FIXME: toytoolkit need a pre-block handler where we can
	 * call this. */
	wl_display_flush_clients(surface->nested->child_display);
}

static void
frame_callback(void *data, struct wl_callback *callback, uint32_t time)
{
	struct nested *nested = data;
	struct nested_surface *surface;

	wl_list_for_each(surface, &nested->surface_list, link)
		flush_surface_frame_callback_list(surface, time);

	if (callback)
		wl_callback_destroy(callback);
}

static const struct wl_callback_listener frame_listener = {
	frame_callback
};

static void
redraw_handler(struct widget *widget, void *data)
{
	struct nested *nested = data;
	cairo_surface_t *surface;
	cairo_t *cr;
	struct rectangle allocation;
	struct wl_callback *callback;
	struct nested_surface *s;

	widget_get_allocation(nested->widget, &allocation);

	surface = window_get_surface(nested->window);

	cr = cairo_create(surface);
	cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
	cairo_rectangle(cr,
			allocation.x,
			allocation.y,
			allocation.width,
			allocation.height);
	cairo_set_source_rgba(cr, 0, 0, 0, 0.8);
	cairo_fill(cr);

	wl_list_for_each(s, &nested->surface_list, link) {
		display_acquire_window_surface(nested->display,
					       nested->window, NULL);

		glBindTexture(GL_TEXTURE_2D, s->texture);
		image_target_texture_2d(GL_TEXTURE_2D, s->image);

		display_release_window_surface(nested->display,
					       nested->window);

		cairo_set_operator(cr, CAIRO_OPERATOR_OVER);
		cairo_set_source_surface(cr, s->cairo_surface,
					 allocation.x + 10,
					 allocation.y + 10);
		cairo_rectangle(cr, allocation.x + 10,
				allocation.y + 10,
				allocation.width - 10,
				allocation.height - 10);

		cairo_fill(cr);
	}

	cairo_destroy(cr);

	cairo_surface_destroy(surface);

	callback = wl_surface_frame(window_get_wl_surface(nested->window));
	wl_callback_add_listener(callback, &frame_listener, nested);
}

static void
keyboard_focus_handler(struct window *window,
		       struct input *device, void *data)
{
	struct nested *nested = data;

	window_schedule_redraw(nested->window);
}

static void
handle_child_data(struct task *task, uint32_t events)
{
	struct nested *nested = container_of(task, struct nested, child_task);
	struct wl_event_loop *loop;

	loop = wl_display_get_event_loop(nested->child_display);

	wl_event_loop_dispatch(loop, -1);
	wl_display_flush_clients(nested->child_display);
}

struct nested_client {
	struct wl_client *client;
	pid_t pid;
};

static struct nested_client *
launch_client(struct nested *nested, const char *path)
{
	int sv[2];
	pid_t pid;
	struct nested_client *client;

	client = malloc(sizeof *client);
	if (client == NULL)
		return NULL;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
		fprintf(stderr, "launch_client: "
			"socketpair failed while launching '%s': %m\n",
			path);
		free(client);
		return NULL;
	}

	pid = fork();
	if (pid == -1) {
		close(sv[0]);
		close(sv[1]);
		free(client);
		fprintf(stderr, "launch_client: "
			"fork failed while launching '%s': %m\n", path);
		return NULL;
	}

	if (pid == 0) {
		int clientfd;
		char s[32];

		/* SOCK_CLOEXEC closes both ends, so we dup the fd to
		 * get a non-CLOEXEC fd to pass through exec. */
		clientfd = dup(sv[1]);
		if (clientfd == -1) {
			fprintf(stderr, "compositor: dup failed: %m\n");
			exit(-1);
		}

		snprintf(s, sizeof s, "%d", clientfd);
		setenv("WAYLAND_SOCKET", s, 1);

		execl(path, path, NULL);

		fprintf(stderr, "compositor: executing '%s' failed: %m\n",
			path);
		exit(-1);
	}

	close(sv[1]);

	client->client = wl_client_create(nested->child_display, sv[0]);
	if (!client->client) {
		close(sv[0]);
		free(client);
		fprintf(stderr, "launch_client: "
			"wl_client_create failed while launching '%s'.\n",
			path);
		return NULL;
	}

	client->pid = pid;

	return client;
}

static void
destroy_surface(struct wl_resource *resource)
{
	struct nested_surface *surface = wl_resource_get_user_data(resource);
	struct nested_frame_callback *cb, *next;

	wl_list_for_each_safe(cb, next,
			      &surface->frame_callback_list, link)
		wl_resource_destroy(cb->resource);

	wl_list_for_each_safe(cb, next,
			      &surface->pending.frame_callback_list, link)
		wl_resource_destroy(cb->resource);

	nested_buffer_reference(&surface->buffer_ref, NULL);

	pixman_region32_fini(&surface->pending.damage);

	wl_list_remove(&surface->link);

	free(surface);
}

static void
surface_destroy(struct wl_client *client, struct wl_resource *resource)
{
	wl_resource_destroy(resource);
}

static void
surface_attach(struct wl_client *client,
	       struct wl_resource *resource,
	       struct wl_resource *buffer_resource, int32_t sx, int32_t sy)
{
	struct nested_surface *surface = wl_resource_get_user_data(resource);
	struct nested *nested = surface->nested;
	struct nested_buffer *buffer = NULL;

	if (buffer_resource) {
		int format;

		if (!query_buffer(nested->egl_display, (void *) buffer_resource,
				  EGL_TEXTURE_FORMAT, &format)) {
			wl_resource_post_error(buffer_resource,
					       WL_DISPLAY_ERROR_INVALID_OBJECT,
					       "attaching non-egl wl_buffer");
			return;
		}

		switch (format) {
		case EGL_TEXTURE_RGB:
		case EGL_TEXTURE_RGBA:
			break;
		default:
			wl_resource_post_error(buffer_resource,
					       WL_DISPLAY_ERROR_INVALID_OBJECT,
					       "invalid format");
			return;
		}

		buffer = nested_buffer_from_resource(buffer_resource);
		if (buffer == NULL) {
			wl_client_post_no_memory(client);
			return;
		}
	}

	if (surface->pending.buffer)
		wl_list_remove(&surface->pending.buffer_destroy_listener.link);

	surface->pending.buffer = buffer;
	surface->pending.newly_attached = 1;
	if (buffer) {
		wl_signal_add(&buffer->destroy_signal,
			      &surface->pending.buffer_destroy_listener);
	}
}

static void
nested_surface_attach(struct nested_surface *surface,
		      struct nested_buffer *buffer)
{
	struct nested *nested = surface->nested;
	EGLint width, height;
	cairo_device_t *device;

	nested_buffer_reference(&surface->buffer_ref, buffer);

	if (surface->image != EGL_NO_IMAGE_KHR)
		destroy_image(nested->egl_display, surface->image);
	if (surface->cairo_surface)
		cairo_surface_destroy(surface->cairo_surface);

	surface->image = create_image(nested->egl_display, NULL,
				      EGL_WAYLAND_BUFFER_WL, buffer->resource,
				      NULL);
	if (surface->image == EGL_NO_IMAGE_KHR) {
		fprintf(stderr, "failed to create img\n");
		return;
	}

	query_buffer(nested->egl_display, (void *) buffer->resource,
		     EGL_WIDTH, &width);
	query_buffer(nested->egl_display, (void *) buffer->resource,
		     EGL_HEIGHT, &height);

	device = display_get_cairo_device(nested->display);
	surface->cairo_surface = 
		cairo_gl_surface_create_for_texture(device,
						    CAIRO_CONTENT_COLOR_ALPHA,
						    surface->texture,
						    width, height);
}

static void
surface_damage(struct wl_client *client,
	       struct wl_resource *resource,
	       int32_t x, int32_t y, int32_t width, int32_t height)
{
	struct nested_surface *surface = wl_resource_get_user_data(resource);

	pixman_region32_union_rect(&surface->pending.damage,
				   &surface->pending.damage,
				   x, y, width, height);
}

static void
destroy_frame_callback(struct wl_resource *resource)
{
	struct nested_frame_callback *callback = wl_resource_get_user_data(resource);

	wl_list_remove(&callback->link);
	free(callback);
}

static void
surface_frame(struct wl_client *client,
	      struct wl_resource *resource, uint32_t id)
{
	struct nested_frame_callback *callback;
	struct nested_surface *surface = wl_resource_get_user_data(resource);

	callback = malloc(sizeof *callback);
	if (callback == NULL) {
		wl_resource_post_no_memory(resource);
		return;
	}

	callback->resource = wl_resource_create(client,
						&wl_callback_interface, 1, id);
	wl_resource_set_implementation(callback->resource, NULL, callback,
				       destroy_frame_callback);

	wl_list_insert(surface->pending.frame_callback_list.prev,
		       &callback->link);
}

static void
surface_set_opaque_region(struct wl_client *client,
			  struct wl_resource *resource,
			  struct wl_resource *region_resource)
{
	fprintf(stderr, "surface_set_opaque_region\n");
}

static void
surface_set_input_region(struct wl_client *client,
			 struct wl_resource *resource,
			 struct wl_resource *region_resource)
{
	fprintf(stderr, "surface_set_input_region\n");
}

static void
empty_region(pixman_region32_t *region)
{
	pixman_region32_fini(region);
	pixman_region32_init(region);
}

static void
surface_commit(struct wl_client *client, struct wl_resource *resource)
{
	struct nested_surface *surface = wl_resource_get_user_data(resource);
	struct nested *nested = surface->nested;

	/* wl_surface.attach */
	if (surface->pending.newly_attached)
		nested_surface_attach(surface, surface->pending.buffer);

	if (surface->pending.buffer) {
		wl_list_remove(&surface->pending.buffer_destroy_listener.link);
		surface->pending.buffer = NULL;
	}
	surface->pending.newly_attached = 0;

	/* wl_surface.damage */
	empty_region(&surface->pending.damage);

	/* wl_surface.frame */
	wl_list_insert_list(&surface->frame_callback_list,
			    &surface->pending.frame_callback_list);
	wl_list_init(&surface->pending.frame_callback_list);

	window_schedule_redraw(nested->window);
}

static void
surface_set_buffer_transform(struct wl_client *client,
			     struct wl_resource *resource, int transform)
{
	fprintf(stderr, "surface_set_buffer_transform\n");
}

static const struct wl_surface_interface surface_interface = {
	surface_destroy,
	surface_attach,
	surface_damage,
	surface_frame,
	surface_set_opaque_region,
	surface_set_input_region,
	surface_commit,
	surface_set_buffer_transform
};

static void
surface_handle_pending_buffer_destroy(struct wl_listener *listener, void *data)
{
	struct nested_surface *surface =
		container_of(listener, struct nested_surface,
			     pending.buffer_destroy_listener);

	surface->pending.buffer = NULL;
}

static void
compositor_create_surface(struct wl_client *client,
			  struct wl_resource *resource, uint32_t id)
{
	struct nested *nested = wl_resource_get_user_data(resource);
	struct nested_surface *surface;
	
	surface = zalloc(sizeof *surface);
	if (surface == NULL) {
		wl_resource_post_no_memory(resource);
		return;
	}

	surface->nested = nested;

	wl_list_init(&surface->frame_callback_list);

	wl_list_init(&surface->pending.frame_callback_list);
	surface->pending.buffer_destroy_listener.notify =
		surface_handle_pending_buffer_destroy;
	pixman_region32_init(&surface->pending.damage);

	display_acquire_window_surface(nested->display,
				       nested->window, NULL);

	glGenTextures(1, &surface->texture);
	glBindTexture(GL_TEXTURE_2D, surface->texture);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);

	display_release_window_surface(nested->display, nested->window);

	surface->resource =
		wl_resource_create(client, &wl_surface_interface, 1, id);

	wl_resource_set_implementation(surface->resource,
				       &surface_interface, surface,
				       destroy_surface);

	wl_list_insert(nested->surface_list.prev, &surface->link);
}

static void
destroy_region(struct wl_resource *resource)
{
	struct nested_region *region = wl_resource_get_user_data(resource);

	pixman_region32_fini(&region->region);
	free(region);
}

static void
region_destroy(struct wl_client *client, struct wl_resource *resource)
{
	wl_resource_destroy(resource);
}

static void
region_add(struct wl_client *client, struct wl_resource *resource,
	   int32_t x, int32_t y, int32_t width, int32_t height)
{
	struct nested_region *region = wl_resource_get_user_data(resource);

	pixman_region32_union_rect(&region->region, &region->region,
				   x, y, width, height);
}

static void
region_subtract(struct wl_client *client, struct wl_resource *resource,
		int32_t x, int32_t y, int32_t width, int32_t height)
{
	struct nested_region *region = wl_resource_get_user_data(resource);
	pixman_region32_t rect;

	pixman_region32_init_rect(&rect, x, y, width, height);
	pixman_region32_subtract(&region->region, &region->region, &rect);
	pixman_region32_fini(&rect);
}

static const struct wl_region_interface region_interface = {
	region_destroy,
	region_add,
	region_subtract
};

static void
compositor_create_region(struct wl_client *client,
			 struct wl_resource *resource, uint32_t id)
{
	struct nested_region *region;

	region = malloc(sizeof *region);
	if (region == NULL) {
		wl_resource_post_no_memory(resource);
		return;
	}

	pixman_region32_init(&region->region);

	region->resource =
		wl_resource_create(client, &wl_region_interface, 1, id);
	wl_resource_set_implementation(region->resource, &region_interface,
				       region, destroy_region);
}

static const struct wl_compositor_interface compositor_interface = {
	compositor_create_surface,
	compositor_create_region
};

static void
compositor_bind(struct wl_client *client,
		void *data, uint32_t version, uint32_t id)
{
	struct nested *nested = data;
	struct wl_resource *resource;

	resource = wl_resource_create(client, &wl_compositor_interface,
				      MIN(version, 3), id);
	wl_resource_set_implementation(resource, &compositor_interface,
				       nested, NULL);
}

static int
nested_init_compositor(struct nested *nested)
{
	const char *extensions;
	struct wl_event_loop *loop;
	int fd, ret;

	wl_list_init(&nested->surface_list);
	nested->child_display = wl_display_create();
	loop = wl_display_get_event_loop(nested->child_display);
	fd = wl_event_loop_get_fd(loop);
	nested->child_task.run = handle_child_data;
	display_watch_fd(nested->display, fd,
			 EPOLLIN, &nested->child_task);

	if (!wl_global_create(nested->child_display,
			      &wl_compositor_interface, 1,
			      nested, compositor_bind))
		return -1;

	wl_display_init_shm(nested->child_display);

	nested->egl_display = display_get_egl_display(nested->display);
	extensions = eglQueryString(nested->egl_display, EGL_EXTENSIONS);
	if (strstr(extensions, "EGL_WL_bind_wayland_display") == NULL) {
		fprintf(stderr, "no EGL_WL_bind_wayland_display extension\n");
		return -1;
	}

	bind_display = (void *) eglGetProcAddress("eglBindWaylandDisplayWL");
	unbind_display = (void *) eglGetProcAddress("eglUnbindWaylandDisplayWL");
	create_image = (void *) eglGetProcAddress("eglCreateImageKHR");
	destroy_image = (void *) eglGetProcAddress("eglDestroyImageKHR");
	query_buffer = (void *) eglGetProcAddress("eglQueryWaylandBufferWL");
	image_target_texture_2d =
		(void *) eglGetProcAddress("glEGLImageTargetTexture2DOES");

	ret = bind_display(nested->egl_display, nested->child_display);
	if (!ret) {
		fprintf(stderr, "failed to bind wl_display\n");
		return -1;
	}

	return 0;
}

static struct nested *
nested_create(struct display *display)
{
	struct nested *nested;

	nested = zalloc(sizeof *nested);
	if (nested == NULL)
		return nested;

	nested->window = window_create(display);
	nested->widget = window_frame_create(nested->window, nested);
	window_set_title(nested->window, "Wayland Nested");
	nested->display = display;

	window_set_user_data(nested->window, nested);
	widget_set_redraw_handler(nested->widget, redraw_handler);
	window_set_keyboard_focus_handler(nested->window,
					  keyboard_focus_handler);

	nested_init_compositor(nested);

	widget_schedule_resize(nested->widget, 400, 400);

	return nested;
}

static void
nested_destroy(struct nested *nested)
{
	widget_destroy(nested->widget);
	window_destroy(nested->window);
	free(nested);
}

int
main(int argc, char *argv[])
{
	struct display *display;
	struct nested *nested;

	display = display_create(&argc, argv);
	if (display == NULL) {
		fprintf(stderr, "failed to create display: %m\n");
		return -1;
	}

	nested = nested_create(display);

	launch_client(nested, "weston-nested-client");

	display_run(display);

	nested_destroy(nested);
	display_destroy(display);

	return 0;
}
