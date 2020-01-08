/**
 * Copyright © 2016-2018 Thincast Technologies Gmbh
 * Copyright © 2016 Hardening <contact@hardening-consulting.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "config.h"

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <linux/input.h>

#include <ogon/backend.h>
#include <ogon/dmgbuf.h>
#include <ogon/version.h>
#include <ogon/service.h>

#include <freerdp/freerdp.h>
#include <freerdp/update.h>
#include <freerdp/input.h>
#include <freerdp/locale/keyboard.h>
#include <freerdp/server/rdpei.h>

#include <winpr/input.h>
#include <winpr/stream.h>
#include <winpr/collections.h>

#include "../shared/helpers.h"
#include "pixman-renderer.h"
#include "compositor-ogon.h"


#define DEFAULT_AXIS_STEP_DISTANCE wl_fixed_from_int(10)
#define OGON_COMMON_LENGTH 6
#define OGON_MODE_FPS 60 * 1000

struct ogon_backend;
struct ogon_output;


/** @brief a seat for ogon */
struct ogon_seat {
	struct weston_seat base;

	UINT32 keyboard_layout;
	UINT32 keyboard_type;

	RdpeiServerContext *rdpei_context;
	HANDLE rdpei_channel;
	struct wl_event_source *rdpei_event_source;

	UINT32 client_id;
	struct wl_array downKeys;
};

/** @brief ogon compositor */
struct ogon_backend {
	struct weston_backend base;
	struct weston_compositor *compositor;

	struct ogon_output *output;
	struct weston_plane not_rendered_plane;
	struct ogon_seat *master_seat;
	bool do_multiseat;
	UINT32 master_seat_client_id;
	wHashTable *extra_seats;
	int n_seats;

	void *service;
	struct wl_event_source *server_event_source;
	struct wl_event_source *client_event_source;

	xkb_mod_index_t capslock_mod_index;
	xkb_mod_index_t numlock_mod_index;
	xkb_mod_index_t scrolllock_mod_index;

	ogon_msg_framebuffer_info rds_fb_infos;
	ogon_msg_framebuffer_sync_reply rds_sync_reply;
	ogon_msg_set_system_pointer rds_set_system_pointer;
};

/** @brief a ogon output */
struct ogon_output {
	struct weston_output base;
	struct ogon_backend *compositor;
	struct wl_event_source *finish_frame_timer;

	int shmid;
	void *buffer;
	void *dmgBuf;
	int pendingShmId;
	bool pendingFrame;
	pixman_image_t *shadow_surface;
	pixman_region32_t damagedRegion;
	bool outputActive;
};


static void
ogon_update_framebuffer(struct ogon_backend *b, pixman_box32_t *rect) {
	struct ogon_output *output = b->output;
	unsigned char *src = (unsigned char *)pixman_image_get_data(output->shadow_surface) +
			(pixman_image_get_stride(output->shadow_surface) * rect->y1) +
			(rect->x1 * 4);
	unsigned char *dst = (unsigned char *)output->buffer +
			(b->rds_fb_infos.scanline * rect->y1) +
			(rect->x1 * 4);
	int widthBytes = (rect->x2 - rect->x1) * 4;
	int y;

	for (y = rect->y1; y < rect->y2; y++) {
		memcpy(dst, src, widthBytes);
		src += pixman_image_get_stride(output->shadow_surface);
		dst += b->rds_fb_infos.scanline;
	}
}

static BOOL
ogon_refresh_region(struct ogon_backend *b, pixman_region32_t *region)
{
	int nrects, i;
	RDP_RECT *rdpRect;
	pixman_box32_t *rect;
	struct ogon_output *output = b->output;

	if (output->dmgBuf) {
		if (ogon_dmgbuf_get_id(output->dmgBuf) != output->pendingShmId) {
			ogon_dmgbuf_free(output->dmgBuf);
			output->dmgBuf = 0;
		}
	}

	if (!output->dmgBuf) {
		output->dmgBuf = ogon_dmgbuf_connect(output->pendingShmId);
		if (!output->dmgBuf) {
			weston_log("%s: unable to bind shmId=%d", __FUNCTION__, output->pendingShmId);
			return -1;
		}
		output->buffer = ogon_dmgbuf_get_data(output->dmgBuf);
	}

	rect = pixman_region32_rectangles(region, &nrects);
	rdpRect = ogon_dmgbuf_get_rects(output->dmgBuf, NULL);

	if (nrects > (int)ogon_dmgbuf_get_max_rects(output->dmgBuf)) {
		/* the region contains too many rectangles, so let's just use the extents
		 * as damaged region */
		pixman_box32_t *extents = pixman_region32_extents(region);
		ogon_dmgbuf_set_num_rects(output->dmgBuf, 1);
		rdpRect->x = extents->x1;
		rdpRect->y = extents->y1;
		rdpRect->width = extents->x2 - extents->x1;
		rdpRect->height = extents->y2 - extents->y1;
		ogon_update_framebuffer(b, extents);
	} else {
		ogon_dmgbuf_set_num_rects(output->dmgBuf, nrects);
		for (i = 0; i < nrects; i++, rect++, rdpRect++) {
			/*weston_log("refresh_rect id=0x%x (%d,%d,%d,%d)\n", output->pendingShmId, rect->x1, rect->y1, rect->x2, rect->y2);*/
			ogon_update_framebuffer(b, rect);

			rdpRect->x = rect->x1;
			rdpRect->y = rect->y1;
			rdpRect->width = rect->x2 - rect->x1;
			rdpRect->height = rect->y2 - rect->y1;
		}
	}

	pixman_region32_clear(region);

	b->rds_sync_reply.bufferId = output->pendingShmId;
	output->pendingFrame = false;

	return ogon_service_write_message(b->service, OGON_SERVER_FRAMEBUFFER_SYNC_REPLY,
			(ogon_message *)&b->rds_sync_reply);
}


static void
ogon_output_start_repaint_loop(struct weston_output *output)
{
	struct timespec ts;

	clock_gettime(output->compositor->presentation_clock, &ts);
	weston_output_finish_frame(output, &ts, WP_PRESENTATION_FEEDBACK_INVALID);
}

static int
ogon_output_repaint(struct weston_output *output_base, pixman_region32_t *damage)
{
	struct ogon_output *output = container_of(output_base, struct ogon_output, base);
	struct weston_compositor *ec = output->base.compositor;

	pixman_region32_union(&output->damagedRegion, &output->damagedRegion, damage);

	pixman_renderer_output_set_buffer(output_base, output->shadow_surface);
	ec->renderer->repaint_output(&output->base, damage);

	if (output->compositor->client_event_source && output->pendingFrame)
		ogon_refresh_region(output->compositor, &output->damagedRegion);

	pixman_region32_subtract(&ec->primary_plane.damage, &ec->primary_plane.damage, damage);

	wl_event_source_timer_update(output->finish_frame_timer, 10);
	return 0;
}

static void
ogon_all_keys_up(struct ogon_backend *b, struct ogon_seat *seat);

static void
ogon_kill_client(struct ogon_backend *b) {
	struct ogon_seat *seat;

	wl_event_source_remove(b->client_event_source);
	b->client_event_source = 0;
	if (b->master_seat) {
		seat = b->master_seat;
		seat->keyboard_layout = 0;
		seat->keyboard_type = 0;

		ogon_all_keys_up(b, seat);
		weston_seat_release_pointer(&seat->base);
		weston_seat_release_keyboard(&seat->base);
	}

	b->master_seat = NULL;
	ogon_service_kill_client(b->service);

	b->output->pendingShmId = -1;

	if (b->extra_seats) {
		ULONG_PTR *keys = NULL, *key;
		int i, nkeys;
		if ((nkeys = HashTable_GetKeys(b->extra_seats, &keys)) < 0) {
			weston_log("unable to retrieve seat keys\n");
			goto out;
		}

		key = keys;
		for (i = 0; i < nkeys; i++, key++) {
			seat = HashTable_GetItemValue(b->extra_seats, (void *)*key);
			if (!seat) {
				weston_log("weird, unable to retrieve value for key %d", (int)*key);
				continue;
			}

			ogon_all_keys_up(b, seat);
			weston_seat_release_pointer(&seat->base);
			weston_seat_release_keyboard(&seat->base);
		}
		free(keys);
		HashTable_Clear(b->extra_seats);
	}

out:
	b->n_seats = 0;
}

static void
ogon_output_destroy(struct weston_output *output_base)
{
	struct ogon_output *output = container_of(output_base, struct ogon_output, base);

	pixman_image_unref(output->shadow_surface);
	wl_event_source_remove(output->finish_frame_timer);
	pixman_region32_fini(&output->damagedRegion);

	pixman_renderer_output_destroy(output_base);
	free(output);
}

static int
finish_frame_handler(void *data)
{
	ogon_output_start_repaint_loop(data);
	return 1;
}


static struct weston_mode *
ogon_insert_new_mode(struct weston_output *output, int width, int height, int rate) {
	struct weston_mode *ret;
	ret = zalloc(sizeof *ret);
	if(!ret)
		return NULL;
	ret->width = width;
	ret->height = height;
	ret->refresh = rate;
	wl_list_insert(&output->mode_list, &ret->link);
	return ret;
}

static struct weston_mode *
ensure_matching_mode(struct weston_output *output, struct weston_mode *target) {
	struct weston_mode *local;

	wl_list_for_each(local, &output->mode_list, link) {
		if((local->width == target->width) && (local->height == target->height))
			return local;
	}

	return ogon_insert_new_mode(output, target->width, target->height, OGON_MODE_FPS);
}


static BOOL
ogon_send_shared_framebuffer(struct ogon_backend *b) {
	return ogon_service_write_message(b->service, OGON_SERVER_FRAMEBUFFER_INFO,
			(ogon_message *)&b->rds_fb_infos);
}



static int
ogon_switch_mode(struct weston_output *output, struct weston_mode *mode)
{
	struct weston_mode *localMode;
	pixman_image_t *new_shadow_buffer;
	struct ogon_output *rdsOutput = container_of(output, struct ogon_output, base);
	struct ogon_backend *b = rdsOutput->compositor;

	localMode = ensure_matching_mode(output, mode);
	if (!localMode) {
		weston_log("unable to ensure the requested mode\n");
		return -ENOMEM;
	}

	if(localMode == output->current_mode)
		return 0;

	output->current_mode->flags &= ~WL_OUTPUT_MODE_CURRENT;

	output->current_mode = localMode;
	output->current_mode->flags |= WL_OUTPUT_MODE_CURRENT;

	pixman_renderer_output_destroy(output);
	pixman_renderer_output_create(output);

	new_shadow_buffer = pixman_image_create_bits(PIXMAN_x8r8g8b8, mode->width,
			mode->height, 0, mode->width * 4);
	pixman_image_composite32(PIXMAN_OP_SRC, rdsOutput->shadow_surface, 0,
			new_shadow_buffer, 0, 0,
			0, 0,
			0, 0, mode->width, mode->height
	);

	pixman_image_unref(rdsOutput->shadow_surface);
	rdsOutput->shadow_surface = new_shadow_buffer;

	pixman_region32_clear(&rdsOutput->damagedRegion);
	pixman_region32_union_rect(&rdsOutput->damagedRegion, &rdsOutput->damagedRegion,
			0, 0, mode->width, mode->height);

	b->rds_fb_infos.width = mode->width;
	b->rds_fb_infos.height = mode->height;
	b->rds_fb_infos.scanline = mode->width * 4;

	if (b->client_event_source) {
		// we have a connected peer so we have to inform it of the new configuration
		ogon_send_shared_framebuffer(b);
	}
	return 0;
}

static inline void
set_rdp_pointer_andmask_bit(char *data, int x, int y, int width, int height, bool on)
{
	/**
	 * MS-RDPBCGR 2.2.9.1.1.4.4:
	 * andMaskData (variable): A variable-length array of bytes.
	 * Contains the 1-bpp, bottom-up AND mask scan-line data.
	 * The AND mask is padded to a 2-byte boundary for each encoded scan-line.
	 */
	int stride, offset;
	char mvalue;

	if (width < 0 || x < 0 || x >= width) {
		return;
	}

	if (height < 0 || y < 0 || y >= height) {
		return;
	}

	stride = ((width + 15) >> 4) * 2;
	offset = stride * (height-1-y) + (x >> 3);
	mvalue = 0x80 >> (x & 7);

	if (on) {
		data[offset] |= mvalue;
	} else {
		data[offset] &= ~mvalue;
	}
}

static void
computeMaskAndData(struct weston_surface *image, const uint32_t *src, uint32_t *data, char *mask) {
	unsigned int p;
	int32_t x, y;

	for (y = 0; y < image->height; y++)	{
		for (x = 0; x < image->width; x++) {
			p = src[y * image->width + x];
			if (p >> 24) {
				set_rdp_pointer_andmask_bit(mask, x, y, image->width, image->height, false);

				data[(image->height - y - 1) * image->width + x] = p;
			}
		}
	}
}

static struct weston_plane *
treat_master_seat_pointer(struct weston_compositor *ec, struct ogon_backend *b,
		struct weston_view *ev, struct weston_surface *es, struct weston_pointer *main_pointer)
{

	/* don't support any kind of transformation */
	if (ev->transform.enabled || ev->geometry.scissor_enabled)
		return &ec->primary_plane;

	if (es) {
		ogon_msg_set_pointer msg;
		struct wl_shm_buffer *shmbuf;
		char data[96 * 96 * 4];
		char mask[96 * 96 / 8];

		if (!pixman_region32_not_empty(&es->damage))
			return &b->not_rendered_plane;

		if ((es->width > 96) || (es->height > 96)) /* pointer can't be bigger than 96 x 96 */
			return &ec->primary_plane;

		if (!ev->surface->buffer_ref.buffer)
			return &ec->primary_plane;

		shmbuf = wl_shm_buffer_get(ev->surface->buffer_ref.buffer->resource);
		if (!shmbuf)
			return &ec->primary_plane;;
		if (wl_shm_buffer_get_format(shmbuf) != WL_SHM_FORMAT_ARGB8888)
			return &ec->primary_plane;

		memset(data, 0x00, 96 * 96 * 4);
		memset(mask, 0xff, 96 * 96 / 8);

		msg.xPos = main_pointer->hotspot_x;
		msg.yPos = main_pointer->hotspot_y;
		msg.width = es->width;
		msg.height = es->height;
		msg.xorBpp = 32;
		msg.andMaskData = (BYTE *)mask;
		msg.lengthAndMask = ((es->width + 15) >> 4) * 2 * es->height;
		msg.xorMaskData = (BYTE *)data;
		msg.lengthXorMask = 4 * es->width * es->height;
		msg.clientId = b->do_multiseat ? b->master_seat_client_id : 0;

		computeMaskAndData(es, (uint32_t *)wl_shm_buffer_get_data(shmbuf), (uint32_t *)data, mask);

		if (!ogon_service_write_message(b->service, OGON_SERVER_SET_POINTER, (ogon_message *)&msg)) {
			weston_log("error when sending pointer to client");
		}

		return &b->not_rendered_plane;
	}

	return &ec->primary_plane;
}

static void
ogon_assign_planes(struct weston_output *output_base)
{
	struct weston_compositor *ec = output_base->compositor;
	struct ogon_backend *b = (struct ogon_backend *)ec->backend;
	struct weston_view *ev, *next;
	struct weston_pointer *main_pointer = NULL;

	if (b && b->master_seat)
		main_pointer = b->master_seat->base.pointer_state;

	wl_list_for_each_safe(ev, next, &output_base->compositor->view_list, link) {
		struct weston_surface *es = ev->surface;
		struct weston_plane *target_plane;

		target_plane = &ec->primary_plane;
		if ((b->n_seats == 1) && main_pointer && (main_pointer->sprite == ev))
			target_plane = treat_master_seat_pointer(ec, b, ev, es, main_pointer);

		weston_view_move_to_plane(ev, target_plane);
		ev->psf_flags = 0;
	}

}

struct ogon_simple_mode {
	int width;
	int height;
};
static struct ogon_simple_mode standard_modes[] = {
		{640, 480},
		{800, 600},
		{1024, 768},
		{1280, 1024},

		{0, 0}, /* /!\ the last one /!\ */
};


static int
ogon_compositor_create_output(struct ogon_backend *b, int width, int height)
{
	int i;
	struct ogon_output *output;
	struct wl_event_loop *loop;
	struct weston_mode *currentMode, *next, *extraMode;
	ogon_msg_framebuffer_info *fb_infos;
	ogon_msg_set_system_pointer *system_pointer;

	output = zalloc(sizeof *output);
	if (output == NULL)
		return -1;

	wl_list_init(&output->base.mode_list);

	currentMode = ogon_insert_new_mode(&output->base, width, height, OGON_MODE_FPS);
	if(!currentMode)
		goto out_free_output;
	currentMode->flags = WL_OUTPUT_MODE_CURRENT | WL_OUTPUT_MODE_PREFERRED;

	for (i = 0; standard_modes[i].width; i++) {
		if (standard_modes[i].width == width && standard_modes[i].height == height)
			continue;

		extraMode = ogon_insert_new_mode(&output->base,
				standard_modes[i].width,
				standard_modes[i].height, OGON_MODE_FPS
		);
		if(!extraMode)
			goto out_output;
	}

	output->base.current_mode = output->base.native_mode = currentMode;
	weston_output_init(&output->base, b->compositor, 0, 0, width, height,
			   WL_OUTPUT_TRANSFORM_NORMAL, 1);

	output->base.make = "weston";
	output->base.model = "ogon";

	output->shmid = -1;
	output->buffer = 0;
	output->outputActive = true;
	output->pendingShmId = -1;
	output->pendingFrame = false;

	fb_infos = &b->rds_fb_infos;
	fb_infos->width = width;
	fb_infos->height = height;
	fb_infos->bitsPerPixel = 32;
	fb_infos->bytesPerPixel = 4;
	fb_infos->userId = (UINT32)getuid();
	fb_infos->scanline = width * 4;
	fb_infos->multiseatCapable = b->do_multiseat;

	system_pointer = &b->rds_set_system_pointer;
	system_pointer->ptrType = SYSPTR_NULL;

	pixman_region32_init(&output->damagedRegion);
	output->shadow_surface = pixman_image_create_bits(PIXMAN_a8r8g8b8,
			width, height,
		    NULL,
		    width * 4);
	if (output->shadow_surface == NULL) {
		weston_log("Failed to create surface for frame buffer.\n");
		goto out_output;
	}

	if (pixman_renderer_output_create(&output->base) < 0)
		goto out_shadow_surface;

	loop = wl_display_get_event_loop(b->compositor->wl_display);
	output->finish_frame_timer = wl_event_loop_add_timer(loop, finish_frame_handler, output);

	output->base.start_repaint_loop = ogon_output_start_repaint_loop;
	output->base.repaint = ogon_output_repaint;
	output->base.destroy = ogon_output_destroy;
	output->base.assign_planes = ogon_assign_planes;
	output->base.set_backlight = NULL;
	output->base.set_dpms = NULL;
	output->base.switch_mode = ogon_switch_mode;
	output->compositor = b;
	b->output = output;

	wl_list_insert(b->compositor->output_list.prev, &output->base.link);
	return 0;

out_shadow_surface:
	pixman_image_unref(output->shadow_surface);
out_output:
	weston_output_destroy(&output->base);

	wl_list_for_each_safe(currentMode, next, &output->base.mode_list, link)
		free(currentMode);
out_free_output:
	free(output);
	return -1;
}

static void
ogon_restore(struct weston_compositor *ec)
{
}

static void
ogon_destroy(struct weston_compositor *ec)
{
	struct ogon_backend *c = (struct ogon_backend *)ec->backend;

	wl_event_source_remove(c->server_event_source);
	c->server_event_source = 0;

	if (c->client_event_source)
		ogon_kill_client(c);

	weston_compositor_shutdown(ec);

	free(ec);
}


struct rdp_to_xkb_keyboard_layout {
	UINT32 rdpLayoutCode;
	const char *xkbLayout;
	const char *xkbVariant;
};


/* table reversed from
	https://github.com/awakecoding/FreeRDP/blob/master/libfreerdp/locale/xkb_layout_ids.c#L811 */
static struct rdp_to_xkb_keyboard_layout rdp_keyboards[] = {
		{KBD_ARABIC_101, "ara", 0},
		{KBD_BULGARIAN, 0, 0},
		{KBD_CHINESE_TRADITIONAL_US, 0},
		{KBD_CZECH, "cz", 0},
		{KBD_CZECH_PROGRAMMERS, "cz", "bksl"},
		{KBD_CZECH_QWERTY, "cz", "qwerty"},
		{KBD_DANISH, "dk", 0},
		{KBD_GERMAN, "de", 0},
		{KBD_GERMAN_NEO, "de", "neo"},
		{KBD_GERMAN_IBM, "de", "qwerty"},
		{KBD_GREEK, "gr", 0},
		{KBD_GREEK_220, "gr", "simple"},
		{KBD_GREEK_319, "gr", "extended"},
		{KBD_GREEK_POLYTONIC, "gr", "polytonic"},
		{KBD_US, "us", 0},
		{KBD_US_ENGLISH_TABLE_FOR_IBM_ARABIC_238_L, "ara", "buckwalter"},
		{KBD_SPANISH, "es", 0},
		{KBD_SPANISH_VARIATION, "es", "nodeadkeys"},
		{KBD_FINNISH, "fi", 0},
		{KBD_FRENCH, "fr", 0},
		{KBD_HEBREW, "il", 0},
		{KBD_HUNGARIAN, "hu", 0},
		{KBD_HUNGARIAN_101_KEY, "hu", "standard"},
		{KBD_ICELANDIC, "is", 0},
		{KBD_ITALIAN, "it", 0},
		{KBD_ITALIAN_142, "it", "nodeadkeys"},
		{KBD_JAPANESE, "jp", 0},
		{KBD_JAPANESE_INPUT_SYSTEM_MS_IME2002, "jp", "kana"},
		{KBD_KOREAN, "kr", 0},
		{KBD_KOREAN_INPUT_SYSTEM_IME_2000, "kr", "kr104"},
		{KBD_DUTCH, "nl", 0},
		{KBD_NORWEGIAN, "no", 0},
		{KBD_POLISH_PROGRAMMERS, "pl", 0},
		{KBD_POLISH_214, "pl", "qwertz"},
//		{KBD_PORTUGUESE_BRAZILIAN_ABN0416, 0},
		{KBD_ROMANIAN, "ro", 0},
		{KBD_RUSSIAN, "ru", 0},
		{KBD_RUSSIAN_TYPEWRITER, "ru", "typewriter"},
		{KBD_CROATIAN, "hr", 0},
		{KBD_SLOVAK, "sk", 0},
		{KBD_SLOVAK_QWERTY, "sk", "qwerty"},
		{KBD_ALBANIAN, 0, 0},
		{KBD_SWEDISH, "se", 0},
		{KBD_THAI_KEDMANEE, "th", 0},
		{KBD_THAI_KEDMANEE_NON_SHIFTLOCK, "th", "tis"},
		{KBD_TURKISH_Q, "tr", 0},
		{KBD_TURKISH_F, "tr", "f"},
		{KBD_URDU, "in", "urd-phonetic3"},
		{KBD_UKRAINIAN, "ua", 0},
		{KBD_BELARUSIAN, "by", 0},
		{KBD_SLOVENIAN, "si", 0},
		{KBD_ESTONIAN, "ee", 0},
		{KBD_LATVIAN, "lv", 0},
		{KBD_LITHUANIAN_IBM, "lt", "ibm"},
		{KBD_FARSI, "af", 0},
		{KBD_VIETNAMESE, "vn", 0},
		{KBD_ARMENIAN_EASTERN, "am", 0},
		{KBD_AZERI_LATIN, 0, 0},
		{KBD_FYRO_MACEDONIAN, "mk", 0},
		{KBD_GEORGIAN, "ge", 0},
		{KBD_FAEROESE, 0, 0},
		{KBD_DEVANAGARI_INSCRIPT, 0, 0},
		{KBD_MALTESE_47_KEY, 0, 0},
		{KBD_NORWEGIAN_WITH_SAMI, "no", "smi"},
		{KBD_KAZAKH, "kz", 0},
		{KBD_KYRGYZ_CYRILLIC, "kg", "phonetic"},
		{KBD_TATAR, "ru", "tt"},
		{KBD_BENGALI, "bd", 0},
		{KBD_BENGALI_INSCRIPT, "bd", "probhat"},
		{KBD_PUNJABI, 0, 0},
		{KBD_GUJARATI, "in", "guj"},
		{KBD_TAMIL, "in", "tam"},
		{KBD_TELUGU, "in", "tel"},
		{KBD_KANNADA, "in", "kan"},
		{KBD_MALAYALAM, "in", "mal"},
		{KBD_HINDI_TRADITIONAL, "in", 0},
		{KBD_MARATHI, 0, 0},
		{KBD_MONGOLIAN_CYRILLIC, "mn", 0},
		{KBD_UNITED_KINGDOM_EXTENDED, "gb", "intl"},
		{KBD_SYRIAC, "syc", 0},
		{KBD_SYRIAC_PHONETIC, "syc", "syc_phonetic"},
		{KBD_NEPALI, "np", 0},
		{KBD_PASHTO, "af", "ps"},
		{KBD_DIVEHI_PHONETIC, 0, 0},
		{KBD_LUXEMBOURGISH, 0, 0},
		{KBD_MAORI, "mao", 0},
		{KBD_CHINESE_SIMPLIFIED_US, 0, 0},
		{KBD_SWISS_GERMAN, "ch", "de_nodeadkeys"},
		{KBD_UNITED_KINGDOM, "gb", 0},
		{KBD_LATIN_AMERICAN, "latam", 0},
		{KBD_BELGIAN_FRENCH, "be", 0},
		{KBD_BELGIAN_PERIOD, "be", "oss_sundeadkeys"},
		{KBD_PORTUGUESE, "pt", 0},
		{KBD_SERBIAN_LATIN, "rs", 0},
		{KBD_AZERI_CYRILLIC, "az", "cyrillic"},
		{KBD_SWEDISH_WITH_SAMI, "se", "smi"},
		{KBD_UZBEK_CYRILLIC, "af", "uz"},
		{KBD_INUKTITUT_LATIN, "ca", "ike"},
		{KBD_CANADIAN_FRENCH_LEGACY, "ca", "fr-legacy"},
		{KBD_SERBIAN_CYRILLIC, "rs", 0},
		{KBD_CANADIAN_FRENCH, "ca", "fr-legacy"},
		{KBD_SWISS_FRENCH, "ch", "fr"},
		{KBD_BOSNIAN, "ba", 0},
		{KBD_IRISH, 0, 0},
		{KBD_BOSNIAN_CYRILLIC, "ba", "us"},
		{KBD_UNITED_STATES_DVORAK, "us", "dvorak"},
		{KBD_PORTUGUESE_BRAZILIAN_ABNT2, "br", "nativo"},
		{KBD_CANADIAN_MULTILINGUAL_STANDARD, "ca", "multix"},
		{KBD_GAELIC, "ie", "CloGaelach"},

		{0x00000000, 0, 0},
};

/* taken from 2.2.7.1.6 Input Capability Set (TS_INPUT_CAPABILITYSET) */
static char *rdp_keyboard_types[] = {
	"",	/* 0: unused */
	"", /* 1: IBM PC/XT or compatible (83-key) keyboard */
	"", /* 2: Olivetti "ICO" (102-key) keyboard */
	"", /* 3: IBM PC/AT (84-key) or similar keyboard */
	"pc105",/* 4: IBM enhanced (101- or 102-key) keyboard */
	"", /* 5: Nokia 1050 and similar keyboards */
	"",	/* 6: Nokia 9140 and similar keyboards */
	"jp106"	/* 7: Japanese keyboard */
};

static struct xkb_keymap *
ogon_retrieve_keymap(UINT32 rdpKbLayout, UINT32 rdpKbType) {
	struct xkb_context *xkbContext;
	struct xkb_rule_names xkbRuleNames;
	struct xkb_keymap *keymap;
	int i;

	memset(&xkbRuleNames, 0, sizeof(xkbRuleNames));
	if(rdpKbType <= 7 && rdpKbType > 0)
		xkbRuleNames.model = rdp_keyboard_types[rdpKbType];
	else
		xkbRuleNames.model = "pc105";

	for(i = 0; rdp_keyboards[i].rdpLayoutCode; i++) {
		if(rdp_keyboards[i].rdpLayoutCode == rdpKbLayout) {
			xkbRuleNames.layout = rdp_keyboards[i].xkbLayout;
			xkbRuleNames.variant = rdp_keyboards[i].xkbVariant;
			break;
		}
	}

	keymap = NULL;
	if(xkbRuleNames.layout) {
		xkbContext = xkb_context_new(0);
		if(!xkbContext) {
			weston_log("unable to create a xkb_context\n");
			return NULL;
		}

		weston_log("looking for keymap %s\n", xkbRuleNames.layout);
		keymap = xkb_keymap_new_from_names(xkbContext, &xkbRuleNames, 0);
	}
	return keymap;
}

static void
ogon_configure_keyboard(struct ogon_backend *b, struct ogon_seat *seat,
		UINT32 layout, UINT32 keyboard_type)
{
	//weston_log("%s: layout=0x%x keyboard_type=%d\n", __FUNCTION__, layout, keyboard_type);
	if (seat->keyboard_layout == layout && seat->keyboard_type == keyboard_type)
		return;

	weston_seat_init_keyboard(&seat->base,
			ogon_retrieve_keymap(layout, keyboard_type)
	);

	seat->keyboard_layout = layout;
	seat->keyboard_type = keyboard_type;
}

static void
ogon_update_keyboard_modifiers(struct ogon_backend *b, struct weston_seat *seat,
		bool capsLock, bool numLock, bool scrollLock, bool kanaLock)
{
	uint32_t mods_depressed, mods_latched, mods_locked, group;
	uint32_t serial;
	int numMask, capsMask, scrollMask;

	struct weston_keyboard *keyboard = seat->keyboard_state;
	struct xkb_state *state = keyboard->xkb_state.state;
	struct weston_xkb_info *xkb_info = keyboard->xkb_info;

	mods_depressed = xkb_state_serialize_mods(state, XKB_STATE_DEPRESSED);
	mods_latched = xkb_state_serialize_mods(state, XKB_STATE_LATCHED);
	mods_locked = xkb_state_serialize_mods(state, XKB_STATE_LOCKED);
	group = xkb_state_serialize_group(state, XKB_STATE_EFFECTIVE);

	numMask = (1 << xkb_info->mod2_mod);
	capsMask = (1 << xkb_info->caps_mod);
	scrollMask = (1 << xkb_info->scroll_led); // TODO: don't rely on the led status

	mods_locked = capsLock ? (mods_locked | capsMask) : (mods_locked & ~capsMask);
	mods_locked = numLock ? (mods_locked | numMask) : (mods_locked & ~numMask);
	mods_locked = scrollLock ? (mods_locked | scrollMask) : (mods_locked & ~scrollMask);

	xkb_state_update_mask(state, mods_depressed, mods_latched, mods_locked, 0, 0, group);

	serial = wl_display_next_serial(b->compositor->wl_display);
	notify_modifiers(seat, serial);
}

static BOOL
ogon_send_disable_pointer(struct ogon_backend *b, UINT32 connId) {
	b->rds_set_system_pointer.clientId = connId;

	return ogon_service_write_message(b->service, OGON_SERVER_SET_SYSTEM_POINTER,
			(ogon_message *)&b->rds_set_system_pointer);
}

static struct ogon_seat *
retrieve_seat(struct ogon_backend *b, UINT32 id) {
	struct ogon_seat *ret;

	if (!b->do_multiseat)
		return b->master_seat;

	if (b->master_seat_client_id == id)
		return b->master_seat;

	if (!HashTable_Contains(b->extra_seats, (void *)(size_t)id)) {
		weston_log("no seat registered for connection %d\n", (int)id);
		return NULL;
	}

	ret = (struct ogon_seat *)HashTable_GetItemValue(b->extra_seats, (void *)(size_t)id);
	if (!ret)
		weston_log("no seat registered for connection %d(main=%d)\n", (int)id, (int)b->master_seat_client_id);
	return ret;
}

static UINT
rdpei_onClientReady(RdpeiServerContext *context) {
	struct ogon_backend *b = (struct ogon_backend *)context->user_data;
	if ((context->clientVersion != RDPINPUT_PROTOCOL_V10) && (context->clientVersion != RDPINPUT_PROTOCOL_V101))
		weston_log("strange got an unexpected client version 0x%x", context->clientVersion);

	if (context->protocolFlags & READY_FLAGS_DISABLE_TIMESTAMP_INJECTION)
		weston_log("don't take in account the timestamps\n");

	weston_seat_init_touch(&b->master_seat->base);
	return CHANNEL_RC_OK;
}

static UINT
rdpei_onTouchEvent(RdpeiServerContext *context, RDPINPUT_TOUCH_EVENT *touchEvent) {
	struct ogon_backend *b = (struct ogon_backend *)context->user_data;
	UINT16 i;
	UINT32 j;

	for (i = 0; i < touchEvent->frameCount; i++) {
		RDPINPUT_TOUCH_FRAME *frame = &touchEvent->frames[i];

		notify_touch_frame(&b->master_seat->base);

		for (j = 0; j < frame->contactCount; j++) {
			RDPINPUT_CONTACT_DATA *data = &frame->contacts[j];
			int flags = 0;

			/*weston_log("%s: id=%d flags=0x%x up=%d down=%d update=%d\n", __FUNCTION__, data->contactId,
					data->contactFlags, data->contactFlags & CONTACT_FLAG_UP, data->contactFlags & CONTACT_FLAG_DOWN,
					data->contactFlags & CONTACT_FLAG_UPDATE);*/
			if (data->contactFlags & CONTACT_FLAG_UP)
				flags = WL_TOUCH_UP;
			else if (data->contactFlags & CONTACT_FLAG_DOWN) {
				flags = (data->contactFlags & CONTACT_FLAG_UPDATE) ? WL_TOUCH_MOTION : WL_TOUCH_DOWN;
			} else if (data->contactFlags & CONTACT_FLAG_UPDATE)
				flags = WL_TOUCH_MOTION;

			notify_touch(&b->master_seat->base, weston_compositor_get_time(), data->contactId,
					wl_fixed_from_int(data->x), wl_fixed_from_int(data->y), flags);
		}
	}

	return CHANNEL_RC_OK;
}

static int
ogon_multitouch_activity(int fd, uint32_t mask, void *data) {
	struct ogon_backend *c = (struct ogon_backend *)data;
	int ret;

	if (!c->master_seat)
		return 0;

	ret = rdpei_server_handle_messages(c->master_seat->rdpei_context);
	if (ret != CHANNEL_RC_OK) {
		weston_log("%s: disconnected !!!", __FUNCTION__);
		return -1;
	}

	return 0;
}

static int
ogon_configure_multitouch(struct ogon_backend *b, struct ogon_seat *seat) {
	struct wl_event_loop *loop;
	int fd;
	RdpeiServerContext *rdpei_context;

	seat->rdpei_context = rdpei_context = rdpei_server_context_new(WTS_CURRENT_SERVER_HANDLE);
	rdpei_context->user_data = b;
	rdpei_context->onClientReady = rdpei_onClientReady;
	rdpei_context->onTouchEvent = rdpei_onTouchEvent;
	if (rdpei_server_init(rdpei_context) != CHANNEL_RC_OK) {
		weston_log("no multitouch support\n");
		return 0;
	}

	if (rdpei_server_send_sc_ready(rdpei_context, RDPINPUT_PROTOCOL_V101) != CHANNEL_RC_OK) {
		weston_log("error sending first multitouch packet");
		return -1;
	}

	seat->rdpei_channel = rdpei_server_get_event_handle(rdpei_context);
	if (!seat->rdpei_channel || seat->rdpei_channel == INVALID_HANDLE_VALUE) {
		weston_log("error retrieving the RDPEI channel");
		return -1;
	}

	fd = GetEventFileDescriptor(seat->rdpei_channel);
	if (fd < 0) {
		weston_log("invalid RDPEI file descriptor");
		return -1;
	}

	loop = wl_display_get_event_loop(b->compositor->wl_display);
	seat->rdpei_event_source = wl_event_loop_add_fd(loop, fd, WL_EVENT_READABLE, ogon_multitouch_activity, b);

	return 0;
}


static int
write_pipe_rds_client_message(int fd, BYTE* value, int size) {
	int written;
	int totalWritten = 0;

	while (totalWritten != size) {
		written = write(fd, value + totalWritten, size - totalWritten);
		if (written < 0) {
			weston_log("%s: socket(%d) for message display closed unexpected\n", __FUNCTION__, fd);
			close(fd);
			return -1;
		}
		totalWritten += written;
	}
	return written;
}

static int
read_pipe_rds_client_message(int fd, BYTE* buffer, int size)
{
	int currentRead;
	int totalBytes = 0;
	while (totalBytes != size) {
		currentRead = read(fd, buffer + totalBytes, size - totalBytes);
		if (currentRead < 1) {
			weston_log("%s: socket(%d) for message display closed unexpected\n", __FUNCTION__, fd);
			close(fd);
			return 0;
		}
		totalBytes += currentRead;
	}
	return 1;
}


struct ogon_message_process {
	struct wl_event_source *event_source;
	struct ogon_backend *backend;
};

static int
ogon_message_process_activity(int fd, uint32_t mask, void *data) {
	struct ogon_message_process *process = (struct ogon_message_process *)data;
	int result, retValue;
	UINT32 message_id;
	ogon_msg_message_reply rep;

	retValue = -1;
	if (!read_pipe_rds_client_message(fd, (BYTE *)&result, sizeof(result)))
		goto out;
	if (!read_pipe_rds_client_message(fd, (BYTE *)&message_id, sizeof(message_id)))
		goto out;

	close(fd);

	weston_log("%s: sending message with messageid (%d) and result(%d)\n", __FUNCTION__, message_id, result);

	rep.message_id = message_id;
	rep.result = (UINT32)result;

	if (!ogon_service_write_message(process->backend->service, OGON_SERVER_MESSAGE_REPLY, (ogon_message*) &rep)) {
		weston_log("error sending user message reply");
	} else {
		retValue = 0;
	}

out:
	wl_event_source_remove(process->event_source);
	free(process);
	return retValue;
}

#define BUFFER_SIZE_MESSAGE 4 * 1024

static int
ogon_show_user_message(ogon_msg_message *msg) {
	int retVal = 0;
	char buffer[BUFFER_SIZE_MESSAGE];
	char executableName[BUFFER_SIZE_MESSAGE];

	snprintf(executableName, BUFFER_SIZE_MESSAGE, "ogon-message");

	snprintf(buffer, BUFFER_SIZE_MESSAGE, "%s -platform wayland %u %u %u %u \"%s\" \"%s\" \"%s\" \"%s\" \"%s\"",
					executableName,
					msg->message_id, msg->message_type, msg->style, msg->timeout,
					msg->parameter_num > 0 ? msg->parameter1 : "",
					msg->parameter_num > 1 ? msg->parameter2 : "",
					msg->parameter_num > 2 ? msg->parameter3 : "",
					msg->parameter_num > 3 ? msg->parameter4 : "",
					msg->parameter_num > 4 ? msg->parameter5 : ""
					);
	retVal = system(buffer);
	if (!WIFEXITED(retVal)) {
		return -1;
	}

	retVal = WEXITSTATUS(retVal);
	if (retVal == 255) {
		retVal = -1;
	}
	return retVal;
}


static int
ogon_client_activity(int fd, uint32_t mask, void *data) {
	struct ogon_backend *b = (struct ogon_backend *)data;

	if (!(mask & WL_EVENT_READABLE))
		return 0;

	switch (ogon_service_incoming_bytes(b->service, b)) {
	case OGON_INCOMING_BYTES_OK:
	case OGON_INCOMING_BYTES_WANT_MORE_DATA:
		break;
	case OGON_INCOMING_BYTES_BROKEN_PIPE:
	case OGON_INCOMING_BYTES_INVALID_MESSAGE:
	default:
		weston_log("error treating incoming traffic\n");
		ogon_kill_client(b);
		break;
	}

	return 0;
}

static int
ogon_listener_activity(int fd, uint32_t mask, void *data) {
	struct ogon_backend *b = (struct ogon_backend *)data;
	struct wl_event_loop *loop;
	HANDLE client_handle;

	if (b->client_event_source) {
		weston_log("dropping existing client");
		ogon_kill_client(b);
	}

	client_handle = ogon_service_accept(b->service);
	if (client_handle && (client_handle != INVALID_HANDLE_VALUE)) {
		ogon_msg_version version;
		BOOL ret;

		version.versionMajor = OGON_PROTOCOL_VERSION_MAJOR;
		version.versionMinor = OGON_PROTOCOL_VERSION_MINOR;

		char *backendCookie = getenv("OGON_BACKEND_COOKIE");
		if (backendCookie) {
			version.cookie = strdup(backendCookie);
			if (!version.cookie) {
				weston_log("unable to duplicate backend cookie");
				ogon_service_kill_client(b->service);
				return 0;
			}
		} else {
			version.cookie = NULL;
		}

		ret = ogon_service_write_message(b->service, OGON_SERVER_VERSION_REPLY, (ogon_message *)&version);

		free(version.cookie);

		if (!ret) {
			weston_log("failed to write version message to stream");
			ogon_service_kill_client(b->service);
			return 0;
		}

		loop = wl_display_get_event_loop(b->compositor->wl_display);
		b->client_event_source = wl_event_loop_add_fd(loop, ogon_service_client_fd(b->service),
				WL_EVENT_READABLE, ogon_client_activity, b);
	}
	return 0;
}

static struct ogon_seat *
ogon_new_seat(UINT32 clientId) {
	struct ogon_seat *ret;

	ret = zalloc(sizeof(*ret));
	if (!ret)
		return NULL;
	ret->client_id = clientId;

	wl_array_init(&ret->downKeys);
	return ret;
}


static BOOL
rdsCapabilities(struct ogon_backend *b, ogon_msg_capabilities *capabilities) {
	struct ogon_seat *ogonSeat;
	struct ogon_output *output;
	struct weston_mode *currentMode, targetMode;

	if (!b->master_seat) {
		b->master_seat = ogon_new_seat(capabilities->clientId);
		if (!b->master_seat) {
			weston_log("unable to allocate the seat");
			return FALSE;
		}
	}

	ogonSeat = b->master_seat;
	weston_seat_init(&ogonSeat->base, b->compositor, "ogon");
	weston_seat_init_pointer(&ogonSeat->base);
	b->master_seat_client_id = capabilities->clientId;
	weston_log("connection from front connection %d\n", b->master_seat_client_id);

	ogon_configure_keyboard(b, ogonSeat, capabilities->keyboardLayout, capabilities->keyboardType);
	ogon_configure_multitouch(b, ogonSeat);

	currentMode = b->output->base.current_mode;
	if (capabilities->desktopWidth != (UINT32)currentMode->width || capabilities->desktopHeight != (UINT32)currentMode->height) {
		// mode switching will send the shared framebuffer
		targetMode.width = capabilities->desktopWidth;
		targetMode.height = capabilities->desktopHeight;
		weston_output_mode_set_native(&b->output->base, &targetMode, 1);
	} else {
		if (!ogon_send_shared_framebuffer(b)) {
			weston_log("unable to send shared framebuffer, errno=%d\n", errno);
			return FALSE;
		}
	}

	output = b->output;
	if (!pixman_region32_union_rect(&output->damagedRegion, &output->damagedRegion,
									0, 0, capabilities->desktopWidth, capabilities->desktopHeight)) {
		weston_log("unable to mark the full screen as damaged");
		return FALSE;
	}
	b->n_seats = 1;

	return TRUE;
}

static void
ogon_all_keys_up(struct ogon_backend *b, struct ogon_seat *seat) {
	uint32_t *key;

	wl_array_for_each(key, &seat->downKeys) {
		if (!*key)
			continue;
		notify_key(&seat->base, wl_display_next_serial(b->compositor->wl_display),
				*key, WL_KEYBOARD_KEY_STATE_RELEASED, STATE_UPDATE_AUTOMATIC);
		*key = 0;
	}
}

static BOOL
rdsSynchronizeKeyboardEvent(struct ogon_backend *b, DWORD flags, UINT32 clientId) {
	struct ogon_seat *seat;

	seat = retrieve_seat(b, clientId);
	if (!seat)
		return TRUE;

	ogon_all_keys_up(b, seat);

	ogon_update_keyboard_modifiers(b, &seat->base, flags & KBD_SYNC_CAPS_LOCK, flags & KBD_SYNC_NUM_LOCK,
			flags & KBD_SYNC_SCROLL_LOCK, flags & KBD_SYNC_KANA_LOCK
	);

	return TRUE;
}

static bool
ogon_key_down(struct ogon_seat *seat, UINT32 key) {
	uint32_t *k, *freePlace = NULL;

	wl_array_for_each(k, &seat->downKeys) {
		if (!*k)
			freePlace = k;

		if (key == *k) /* already set down */
			return true;
	}

	if (!freePlace) {
		freePlace = wl_array_add(&seat->downKeys, sizeof *k);
		if (!freePlace)
			return false;
	}

	*freePlace = key;
	return true;
}

static void
ogon_key_up(struct ogon_seat *seat, UINT32 key) {
	uint32_t *k;

	wl_array_for_each(k, &seat->downKeys) {
		if (*k == key)
			*k = 0;
	}
}

static BOOL
rdsScancodeKeyboardEvent(struct ogon_backend *b, DWORD flags, DWORD code, DWORD keyboardType, UINT32 clientId) {
	uint32_t key_code;
	enum wl_keyboard_key_state keyState;
	int notify = 0;
	struct ogon_seat *seat = retrieve_seat(b, clientId);
	if (!seat)
		return 0;

	/*weston_log("code=%d flags=0x%x keyb=%d\n", code, flags, keyboardType);*/
	if (flags & KBD_FLAGS_DOWN) {
		keyState = WL_KEYBOARD_KEY_STATE_PRESSED;
		notify = 1;
	} else if (flags & KBD_FLAGS_RELEASE) {
		keyState = WL_KEYBOARD_KEY_STATE_RELEASED;
		notify = 1;
	}

	if(notify) {
		key_code = ogon_rdp_scancode_to_evdev_code(flags, code, keyboardType);

		/*weston_log("code=%x ext=%d vk_code=%x scan_code=%x\n", code, (flags & KBD_FLAGS_EXTENDED) ? 1 : 0,
				vk_code, scan_code);*/
		notify_key(&seat->base, weston_compositor_get_time(), key_code, keyState,
				STATE_UPDATE_AUTOMATIC);

		if (keyState == WL_KEYBOARD_KEY_STATE_PRESSED)
			ogon_key_down(seat, key_code);
		else
			ogon_key_up(seat, key_code);
	}

	return TRUE;
}

static BOOL
rdsUnicodeKeyboardEvent(struct ogon_backend *backend, DWORD flags, DWORD code, UINT32 clientId) {
	weston_log("not handled yet\n");
	return TRUE;
}


static BOOL
rdsMouseEvent(struct ogon_backend *b, DWORD flags, DWORD x, DWORD y, UINT32 clientId) {
	struct ogon_seat *seat = retrieve_seat(b, clientId);
	uint32_t button = 0;
	bool need_frame = false;

	if (!seat) {
		weston_log("seat %d not found here\n", clientId);
		return TRUE;
	}

	/*weston_log("mouse event: x=%d y=%d flags=0x%x\n", x, y, flags);*/
	if (flags & PTR_FLAGS_MOVE) {
		if((int)x < b->output->base.width && (int)y < b->output->base.height) {
			notify_motion_absolute(&seat->base, weston_compositor_get_time(), x, y);
			need_frame = true;
		}
	}

	if (flags & PTR_FLAGS_BUTTON1)
		button = BTN_LEFT;
	else if (flags & PTR_FLAGS_BUTTON2)
		button = BTN_RIGHT;
	else if (flags & PTR_FLAGS_BUTTON3)
		button = BTN_MIDDLE;

	if(button) {
		notify_button(&seat->base, weston_compositor_get_time(), button,
			(flags & PTR_FLAGS_DOWN) ? WL_POINTER_BUTTON_STATE_PRESSED : WL_POINTER_BUTTON_STATE_RELEASED
		);
		need_frame = true;
	}

	if (flags & PTR_FLAGS_WHEEL) {
		struct weston_pointer_axis_event event;
		double value;

		/* DEFAULT_AXIS_STEP_DISTANCE is stolen from compositor-x11.c
		 * The RDP specs says the lower bits of flags contains the "the number of rotation
		 * units the mouse wheel was rotated".
		 *
		 * http://blogs.msdn.com/b/oldnewthing/archive/2013/01/23/10387366.aspx explains the 120 value
		 */
		value = (flags & 0xff) / 120.0;
		if (flags & PTR_FLAGS_WHEEL_NEGATIVE)
			value = -value;

		event.axis = WL_POINTER_AXIS_VERTICAL_SCROLL;
		event.value = DEFAULT_AXIS_STEP_DISTANCE * value;
		event.discrete = (int)value;
		event.has_discrete = true;

		notify_axis(&seat->base, weston_compositor_get_time(), &event);
		need_frame = true;
	}

	if (need_frame)
		notify_pointer_frame(&seat->base);

	return TRUE;
}

static BOOL
rdsExtendedMouseEvent(struct ogon_backend *backend, DWORD flags, DWORD x, DWORD y, UINT32 clientId) {
	weston_log("not handled yet\n");
	return TRUE;
}

static BOOL
rdsFramebufferSyncRequest(struct ogon_backend *b, INT32 bufferId) {
	struct ogon_output *output = b->output;

	output = b->output;
	output->pendingShmId = bufferId;
	output->pendingFrame = true;
	if (pixman_region32_not_empty(&b->output->damagedRegion))
		return ogon_refresh_region(b, &b->output->damagedRegion);

	return TRUE;
}

static BOOL
rdsSbp(struct ogon_backend *backend, ogon_msg_sbp_reply *msg) {
	return TRUE;
}

static BOOL
rdsImmediateSyncRequest(struct ogon_backend *b, INT32 bufferId) {
	struct ogon_output *output = b->output;

	output->pendingShmId = bufferId;
	output->pendingFrame = true;
	return ogon_refresh_region(b, &b->output->damagedRegion);
}

static BOOL
rdsSeatNew(struct ogon_backend *b, ogon_msg_seat_new *seatNew) {
	struct ogon_seat *ogonSeat;
	struct weston_seat *seat;
	char seatName[50];

	if (!b->do_multiseat)
		return TRUE;

	if (HashTable_Contains(b->extra_seats, (void *)(size_t)seatNew->clientId)) {
		weston_log("seat for %d already registered\n", (int)seatNew->clientId);
		return 0;
	}

	snprintf(seatName, sizeof(seatName), "ogon-%d", (int)seatNew->clientId);
	ogonSeat = ogon_new_seat(seatNew->clientId);
	if (!ogonSeat) {
		weston_log("unable to allocate the new seat for %d\n", (int)seatNew->clientId);
		return 0;
	}

	seat = &ogonSeat->base;
	weston_seat_init(seat, b->compositor, seatName);
	weston_seat_init_pointer(seat);
	ogon_configure_keyboard(b, ogonSeat, seatNew->keyboardLayout, seatNew->keyboardType);

	if (b->n_seats == 1) {
		/* start of shadowing, we must switch the main seat to use no client-side
		 * pointer
		 */
		if (!ogon_send_disable_pointer(b, b->master_seat_client_id))
			weston_log("unable to disable client-side pointer on main connection, errno=%d\n", errno);
	}

	if (!ogon_send_disable_pointer(b, seatNew->clientId))
		weston_log("unable to disable client-side pointer on spy connection, errno=%d\n", errno);

	b->n_seats++;

	return HashTable_Add(b->extra_seats, (void *)(size_t)seatNew->clientId, ogonSeat) >= 0 ;
}

static BOOL
rdsSeatRemoved(struct ogon_backend *b, UINT32 clientId) {
	struct ogon_seat *ogonSeat;
	struct weston_seat *seat;

	if (!b->do_multiseat)
		return TRUE;

	if (!HashTable_Contains(b->extra_seats, (void *)(size_t)clientId)) {
		weston_log("no seat for %d\n", (int)clientId);
		return TRUE;
	}

	ogonSeat = (struct ogon_seat *)HashTable_GetItemValue(b->extra_seats, (void *)(size_t)clientId);
	seat = &ogonSeat->base;
	weston_seat_release_keyboard(seat);
	weston_seat_release_pointer(seat);

	/* TODO when safe:
	 weston_seat_release(seat);
	 free(ogonSeat);
	 */

	HashTable_Remove(b->extra_seats, (void *)(size_t)clientId);
	b->n_seats--;

	if (b->n_seats == 1) {
		/* end of shadowing, damage the pointer surface so that it is set again
		 * on the client
		 */
		struct weston_pointer *pointer = b->master_seat->base.pointer_state;
		if (pointer && pointer->sprite && pointer->sprite->surface) {
			struct weston_surface *pointer_surface = pointer->sprite->surface;
			pixman_region32_union_rect(&pointer_surface->damage, &pointer_surface->damage,
					0, 0, pointer_surface->width, pointer_surface->height);
		}
	}

	return TRUE;
}

static BOOL
rdsUserMessage(struct ogon_backend *b, ogon_msg_message *msg) {
	pid_t pid;
	int status;
	int retVal = 0;
	int fd[2];
	struct ogon_message_process *process;

	process = (struct ogon_message_process *)malloc(sizeof(*process));
	if (!process) {
		weston_log("unable to allocate process tracking info\n");
		return FALSE;
	}

	process->backend = b;

	status = pipe(fd);
	if (status != 0) {
		weston_log("%s: pipe creation failed\n", __FUNCTION__);
		free(process);
		return FALSE;
	}

	process->event_source = wl_event_loop_add_fd(wl_display_get_event_loop(b->compositor->wl_display),
			fd[0], WL_EVENT_READABLE, ogon_message_process_activity, process);
	if (!process->event_source) {
		weston_log("%s: unable to create event source\n", __FUNCTION__);
		close(fd[0]);
		close(fd[1]);
		free(process);
		return FALSE;
	}

	pid = fork();
	if (pid == 0) {
		/* child */
		if (fork() == 0) {
			/* Child process closes up input side of pipe */
			close(fd[0]);

			retVal = ogon_show_user_message(msg);

			write_pipe_rds_client_message(fd[1], (BYTE *)&retVal, sizeof(retVal));
			write_pipe_rds_client_message(fd[1], (BYTE *)&msg->message_id, sizeof(msg->message_id));

			close(fd[1]);
			exit(0);
		} else {
			exit(0);
		}
	} else {
		/* parent */
		waitpid(pid, &status, 0);

		/* Parent process closes up output side of pipe */
		close(fd[1]);
	}

	return TRUE;

	return TRUE;
}


static ogon_client_interface rds_callbacks = {
	(pfn_ogon_client_capabilities) rdsCapabilities,
	(pfn_ogon_client_synchronize_keyboard_event) rdsSynchronizeKeyboardEvent,
	(pfn_ogon_client_scancode_keyboard_event) rdsScancodeKeyboardEvent,
	(pfn_ogon_client_unicode_keyboard_event) rdsUnicodeKeyboardEvent,
	(pfn_ogon_client_mouse_event) rdsMouseEvent,
	(pfn_ogon_client_extended_mouse_event) rdsExtendedMouseEvent,
	(pfn_ogon_client_framebuffer_sync_request) rdsFramebufferSyncRequest,
	(pfn_ogon_client_sbp) rdsSbp,
	(pfn_ogon_client_immediate_sync_request) rdsImmediateSyncRequest,
	(pfn_ogon_client_seat_new) rdsSeatNew,
	(pfn_ogon_client_seat_removed) rdsSeatRemoved,
	(pfn_ogon_client_message) rdsUserMessage
};

static struct ogon_backend *
ogon_backend_create(struct weston_compositor *compositor,
		struct weston_ogon_backend_config *config)
{
	struct ogon_backend *b;
	struct wl_event_loop *loop;
	HANDLE server_handle;

	b = zalloc(sizeof *b);
	if (b == NULL)
		return NULL;

	b->compositor = compositor;
	b->base.destroy = ogon_destroy;
	b->base.restore = ogon_restore;
	b->do_multiseat = config->do_multiseat;

	if (b->do_multiseat) {
		b->extra_seats = HashTable_New(FALSE);
		if (!b->extra_seats)
			goto err_compositor;
	}

	if (weston_compositor_set_presentation_clock_software(compositor) < 0)
		goto err_seats;

	if (pixman_renderer_init(b->compositor) < 0)
		goto err_seats;

	if (ogon_compositor_create_output(b, config->width, config->height) < 0)
		goto err_seats;

	weston_plane_init(&b->not_rendered_plane, compositor, 0, 0);

	compositor->capabilities |= WESTON_CAP_ARBITRARY_MODES;

	b->service = ogon_service_new(config->session_id, "Weston");
	if (!b->service) {
		weston_log("unable to create the weston service\n");
		goto err_output;
	}

	ogon_service_set_callbacks(b->service, &rds_callbacks);

	server_handle = ogon_service_bind_endpoint(b->service);
	if ((server_handle == NULL) || (server_handle == INVALID_HANDLE_VALUE)) {
		weston_log("unable to bind the endpoint of the weston service\n");
		goto err_service;
	}

	loop = wl_display_get_event_loop(b->compositor->wl_display);
	b->server_event_source = wl_event_loop_add_fd(loop, ogon_service_server_fd(b->service),
			WL_EVENT_READABLE, ogon_listener_activity, b);
	if (!b->server_event_source) {
		weston_log("unable to add fd to event loop");
		goto err_service;
	}

	compositor->backend = &b->base;
	return b;

err_service:
	ogon_service_free(b->service);
err_output:
	weston_output_destroy(&b->output->base);
err_seats:
	HashTable_Free(b->extra_seats);
err_compositor:
	weston_compositor_shutdown(b->compositor);
	free(b);
	return NULL;
}

static void
config_init_to_defaults(struct weston_ogon_backend_config *config)
{
	config->width = 640;
	config->height = 480;
	config->session_id = 0;
	config->do_multiseat = 0;
}

WL_EXPORT int
backend_init(struct weston_compositor *compositor, int *argc, char *argv[],
	     struct weston_config *wconfig,
		 struct weston_backend_config *config_base)
{
	struct ogon_backend *b;
	struct weston_ogon_backend_config config = {{ 0, }};


	if (config_base == NULL ||
		config_base->struct_version != WESTON_OGON_BACKEND_CONFIG_VERSION ||
		config_base->struct_size > sizeof(struct weston_ogon_backend_config)) {
		weston_log("ogon backend config structure is invalid\n");
		return -1;
	}

	config_init_to_defaults(&config);
	memcpy(&config, config_base, config_base->struct_size);

	if (!config.session_id) {
		weston_log("missing session id");
		return -1;
	}

	b = ogon_backend_create(compositor, &config);
	return b ? 0 : -1;
}
