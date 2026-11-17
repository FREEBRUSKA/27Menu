#include <orbis/libkernel.h>
#include <orbis/libsysutil.h>
#include <orbis/libpad.h>
#include <orbis/UserService.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#define MM_NAME "27 MENU"
#define MM_VER  "1.0"
#define POLL_MS 8
#define DBL_MS  350
#define BONES   16

struct Vec3 { float x, y, z; };

static void klog(const char* f, ...) {
    char b[256]; va_list a; va_start(a, f); vsnprintf(b, sizeof b, f, a); va_end(a);
    sceKernelDebugOutText(0, b);
}
static void notify(const char* f, ...) {
    char b[256]; va_list a; va_start(a, f); vsnprintf(b, sizeof b, f, a); va_end(a);
    sceSysUtilSendSystemNotificationWithText(0x11, b);
}

// ================= FONT 5x7 (ASCII 0x20-0x5F) =================
static const unsigned char FONT[64][5] = {
{0,0,0,0,0},{0,0,0x5F,0,0},{0,7,0,7,0},{0x14,0x7F,0x14,0x7F,0x14},
{0x24,0x2A,0x7F,0x2A,0x12},{0x23,0x13,8,0x64,0x62},{0x36,0x49,0x55,0x22,0x50},
{0,5,3,0,0},{0,0x1C,0x22,0x41,0},{0,0x41,0x22,0x1C,0},{0x14,8,0x3E,8,0x14},
{8,8,0x3E,8,8},{0,0x50,0x30,0,0},{8,8,8,8,8},{0,0x60,0x60,0,0},{0x20,0x10,8,4,2},
{0x3E,0x51,0x49,0x45,0x3E},{0,0x42,0x7F,0x40,0},{0x42,0x61,0x51,0x49,0x46},
{0x21,0x41,0x45,0x4B,0x31},{0x18,0x14,0x12,0x7F,0x10},{0x27,0x45,0x45,0x45,0x39},
{0x3C,0x4A,0x49,0x49,0x30},{1,0x71,9,5,3},{0x36,0x49,0x49,0x49,0x36},
{6,0x49,0x49,0x29,0x1E},{0,0x36,0x36,0,0},{0,0x56,0x36,0,0},{8,0x14,0x22,0x41,0},
{0x14,0x14,0x14,0x14,0x14},{0,0x41,0x22,0x14,8},{2,1,0x51,9,6},{0x32,0x49,0x79,0x41,0x3E},
{0x7E,0x11,0x11,0x11,0x7E},{0x7F,0x49,0x49,0x49,0x36},{0x3E,0x41,0x41,0x41,0x22},
{0x7F,0x41,0x41,0x22,0x1C},{0x7F,0x49,0x49,0x49,0x41},{0x7F,9,9,9,1},
{0x3E,0x41,0x49,0x49,0x7A},{0x7F,8,8,8,0x7F},{0,0x41,0x7F,0x41,0},{0x20,0x40,0x41,0x3F,1},
{0x7F,8,0x14,0x22,0x41},{0x7F,0x40,0x40,0x40,0x40},{0x7F,2,0x0C,2,0x7F},
{0x7F,4,8,0x10,0x7F},{0x3E,0x41,0x41,0x41,0x3E},{0x7F,9,9,9,6},{0x3E,0x41,0x51,0x21,0x5E},
{0x7F,9,0x19,0x29,0x46},{0x46,0x49,0x49,0x49,0x31},{1,1,0x7F,1,1},{0x3F,0x40,0x40,0x40,0x3F},
{0x1F,0x20,0x40,0x20,0x1F},{0x3F,0x40,0x38,0x40,0x3F},{0x63,0x14,8,0x14,0x63},
{7,8,0x70,8,7},{0x61,0x51,0x49,0x45,0x43},{0,0x7F,0x41,0x41,0},{2,4,8,0x10,0x20},
{0,0x41,0x41,0x7F,0},{4,2,1,2,4},{0x40,0x40,0x40,0x40,0x40}
};

// ================= PATTERN SCAN =================
static uint64_t modBase(const char* name) {
    size_t n = 0;
    if (sceKernelGetModuleList(0xFF, 0, &n) != 0) return 0;
    static OrbisKernelModule list[256];
    if (sceKernelGetModuleList(0xFF, list, &n) != 0) return 0;
    for (size_t i = 0; i < n; i++) {
        OrbisKernelModuleInfo in;
        memset(&in, 0, sizeof in);
        in.size = sizeof in;
        if (sceKernelGetModuleInfo(list[i], &in) != 0) continue;
        if (strstr(in.name, name)) return (uint64_t)in.segmentInfo[0].address;
    }
    return 0;
}

static uint64_t resolveSig(const char* mod, const char* sig, int32_t off) {
    uint64_t base = modBase(mod);
    if (!base) { klog("[27] modulo assente"); return 0; }
    unsigned char by[64], mk[64]; size_t n = 0;
    for (const char* p = sig; *p && n < 64;) {
        while (*p == ' ') p++;
        if (!*p) break;
        char c1 = *p++, c2 = *p++;
        int h1 = (c1 == '?') ? 0 : ((c1 <= '9') ? c1 - '0' : (c1 | 0x20) - 'a' + 10);
        int h2 = (c2 == '?') ? 0 : ((c2 <= '9') ? c2 - '0' : (c2 | 0x20) - 'a' + 10);
        by[n] = (unsigned char)((h1 << 4) | h2);
        mk[n] = (unsigned char)(((c1 != '?') << 1) | (c2 != '?'));
        n++;
    }
    if (!n) return 0;
    for (uint64_t a = base; a + n < base + 0x4000000; a++) {
        int hit = 1;
        for (size_t j = 0; j < n; j++) {
            unsigned char v = *(unsigned char*)(a + j);
            if ((mk[j] & 2) && (v >> 4) != (by[j] >> 4)) { hit = 0; break; }
            if ((mk[j] & 1) && (v & 15) != (by[j] & 15)) { hit = 0; break; }
        }
        if (hit) return a + off;
    }
    return 0;
}

// ================= HOOK ENGINE =================
static int insnLen(const unsigned char* p) {
    int i = 0;
    for (;;) {
        unsigned char b = p[i];
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) { i++; continue; }
        if (b >= 0x40 && b <= 0x4F) { i++; continue; }
        break;
    }
    unsigned char op = p[i++];
    if (op == 0x0F) {
        unsigned char o2 = p[i++];
        if (o2 == 0x38 || o2 == 0x3A) i++;
    }
    int modrm = 1, imm = 0;
    if (op >= 0x50 && op <= 0x5F) modrm = 0;
    else if (op == 0x90 || op == 0xC3 || op == 0xC9 || op == 0xCC || op == 0x98 || op == 0x99) modrm = 0;
    else if (op == 0xE8 || op == 0xE9) { modrm = 0; imm = 4; }
    else if (op == 0xEB || op == 0x6A) { modrm = 0; imm = 1; }
    else if (op == 0x68) { modrm = 0; imm = 4; }
    else if (op >= 0xB0 && op <= 0xB7) { modrm = 0; imm = 1; }
    else if (op >= 0xB8 && op <= 0xBF) { modrm = 0; imm = 4; }
    if (modrm) {
        unsigned char m = p[i++];
        int mod = m >> 6, rm = m & 7;
        if (mod != 3) {
            if (rm == 4) {
                unsigned char sib = p[i++];
                if (mod == 0 && (sib & 7) == 5) imm += 4;
            }
            if (mod == 0 && rm == 5) imm += 4;
            else if (mod == 1) imm += 1;
            else if (mod == 2) imm += 4;
        }
        if (op == 0x80 || op == 0x83) imm += 1;
        else if (op == 0x81) imm += 4;
        else if (op == 0xC6) imm += 1;
        else if (op == 0xC7) imm += 4;
    }
    return i + imm;
}

static int memPatch(uint64_t a, const void* d, size_t n) {
    if (!a || !d || !n) return 0;
    uintptr_t s = a & ~0xFFFULL, e = (a + n + 0xFFF) & ~0xFFFULL;
    sceKernelMprotect((void*)s, e - s, 7);
    memcpy((void*)a, d, n);
    return 1;
}

static int hookInstall(uint64_t t, void* fn, void** orig) {
    if (!t) return 0;
    unsigned char* p = (unsigned char*)t;
    int len = 0;
    while (len < 5 && len < 16) {
        int l = insnLen(p + len);
        if (l <= 0) return 0;
        len += l;
    }
    void* tr = 0;
    if (sceKernelMmap(0, 0x1000, 7, 0x1002, -1, 0, &tr) != 0 || !tr) return 0;
    unsigned char* tp = (unsigned char*)tr;
    memcpy(tp, p, len);
    tp[len] = 0xE9;
    *(int32_t*)(tp + len + 1) = (int32_t)((uint64_t)(p + len) - (uint64_t)(tp + len + 5));

    uintptr_t pg = t & ~0xFFFULL;
    sceKernelMprotect((void*)pg, 0x1000, 7);
    p[0] = 0xE9;
    *(int32_t*)(p + 1) = (int32_t)((uint64_t)fn - (uint64_t)(p + 5));
    for (int i = 5; i < len; i++) p[i] = 0x90;
    if (orig) *orig = tr;
    return 1;
}

// ================= OVERLAY =================
#define C_BG    0xE6000000u
#define C_RED   0xFF1F1Fu
#define C_DRED  0xFF6A0000u
#define C_WHITE 0xFFFFFFFFu
#define C_BLACK 0xFF000000u

struct OvAttr { void* data; uint32_t w, h, fmt, tiling, aspect, pitch, opt, rsv[3]; };
struct Fb { uint32_t* data; uint32_t pitch, w, h; };

static Fb g_fb[16];
static uint32_t* g_cur;
static uint32_t g_cw = 1920, g_ch = 1080, g_cp;
static int (*o_Flip)(int, int, int, int64_t);
static int (*o_Reg)(int, int, OvAttr*, int);

void frameRender();

static void px(int x, int y, uint32_t c) {
    if (!g_cur || x < 0 || y < 0 || (uint32_t)x >= g_cw || (uint32_t)y >= g_ch) return;
    uint32_t* p = (uint32_t*)((uint8_t*)g_cur + (uint64_t)y * g_cp) + x;
    uint32_t a = c >> 24;
    if (a == 255) { *p = c; return; }
    uint32_t d = *p;
    *p = (((c & 0xFF) * a + (d & 0xFF) * (255 - a)) / 255)
       | (((((c >> 8) & 0xFF) * a + ((d >> 8) & 0xFF) * (255 - a)) / 255) << 8)
       | (((((c >> 16) & 0xFF) * a + ((d >> 16) & 0xFF) * (255 - a)) / 255) << 16)
       | 0xFF000000;
}

static void ovRect(int x, int y, int w, int h, uint32_t c) {
    for (int j = 0; j < h; j++) for (int i = 0; i < w; i++) px(x + i, y + j, c);
}

static void ovLine(int x0, int y0, int x1, int y1, uint32_t c) {
    int dx = x1 - x0, dy = y1 - y0;
    int sx = dx < 0 ? -1 : 1, sy = dy < 0 ? -1 : 1;
    if (dx < 0) dx = -dx;
    if (dy < 0) dy = -dy;
    int err = dx - dy;
    for (;;) {
        px(x0, y0, c);
        if (x0 == x1 && y0 == y1) break;
        int e2 = err << 1;
        if (e2 > -dy) { err -= dy; x0 += sx; }
        if (e2 < dx) { err += dx; y0 += sy; }
    }
}

static int ovTextW(const char* s, int sc) { return (int)strlen(s) * 6 * sc; }

static void ovText(int x, int y, const char* s, uint32_t c, int sc) {
    for (; *s; s++) {
        char ch = *s;
        if (ch >= 'a' && ch <= 'z') ch -= 32;
        if (ch < 0x20 || ch > 0x5F) ch = '?';
        const unsigned char* g = FONT[ch - 0x20];
        for (int col = 0; col < 5; col++)
            for (int row = 0; row < 7; row++)
                if (g[col] & (1 << row)) ovRect(x + col * sc, y + row * sc, sc, sc, c);
        x += 6 * sc;
    }
}

static int h_Reg(int h, int start, OvAttr* a, int n) {
    for (int i = 0; i < n && start + i < 16; i++) {
        g_fb[start + i].data = (uint32_t*)a[i].data;
        g_fb[start + i].pitch = a[i].pitch;
        g_fb[start + i].w = a[i].w;
        g_fb[start + i].h = a[i].h;
    }
    return o_Reg(h, start, a, n);
}

static int h_Flip(int h, int idx, int mode, int64_t arg) {
    if (idx >= 0 && idx < 16 && g_fb[idx].data) {
        g_cur = g_fb[idx].data; g_cp = g_fb[idx].pitch;
        g_cw = g_fb[idx].w; g_ch = g_fb[idx].h;
        frameRender();
        g_cur = 0;
    }
    return o_Flip(h, idx, mode, arg);
}

static int ovInit() {
    int m = sceKernelLoadStartModule("libSceVideoOut.sprx", 0, 0, 0, 0, 0);
    if (m <= 0) { klog("[27] load videoout %d", m); return 0; }
    void *a = 0, *b = 0;
    if (sceKernelDlsym(m, "sceVideoOutSubmitFlip", &a) != 0) { klog("[27] dlsym flip"); return 0; }
    if (sceKernelDlsym(m, "sceVideoOutRegisterBuffers", &b) != 0) { klog("[27] dlsym reg"); return 0; }
    int r1 = hookInstall((uint64_t)a, (void*)h_Flip, (void**)&o_Flip);
    int r2 = hookInstall((uint64_t)b, (void*)h_Reg, (void**)&o_Reg);
    return r1 && r2;
}

// ================= OFFSET R6S (DA RIEMPIRE) =================
#define OF_GAMEMANAGER  0x0000000
#define OF_ENTITYLIST   0x0000000
#define OF_LOCALPLAYER  0x0000000
#define OF_VIEWMATRIX   0x0000000
#define OF_CAMERA       0x0000000
#define OF_CAM_YAW      0x000
#define OF_CAM_PITCH    0x000
#define OF_ENT_PAWN     0x000
#define OF_PAWN_POS     0x000
#define OF_PAWN_BONES   0x000
#define OF_PAWN_TEAM    0x000
#define OF_PAWN_HP      0x000

#define SIG_GM   "48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9"
#define SIG_LIST "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 50 ?? 48 8B D8"

struct R6Player { uint64_t pawn; int team; float hp, dist; Vec3 pos, bones[BONES]; };
struct R6Cfg { int aimbot, silent, esp, norecoil, aimFov, silFov, smooth, espDist; };

static R6Cfg g_cfg = { 0, 0, 0, 0, 8, 5, 4, 150 };
static uint64_t g_base, g_gm, g_list, g_cam;
static float g_vm[16];
static R6Player g_pl[32];
static int g_count;

static int w2s(const Vec3& w, float* sx, float* sy, int sw, int sh) {
    float x = w.x * g_vm[0] + w.y * g_vm[4] + w.z * g_vm[8] + g_vm[12];
    float y = w.x * g_vm[1] + w.y * g_vm[5] + w.z * g_vm[9] + g_vm[13];
    float z = w.x * g_vm[2] + w.y * g_vm[6] + w.z * g_vm[10] + g_vm[14];
    float ww = w.x * g_vm[3] + w.y * g_vm[7] + w.z * g_vm[11] + g_vm[15];
    if (ww < 0.01f) return 0;
    *sx = (x / ww * 0.5f + 0.5f) * sw;
    *sy = (0.5f - y / ww * 0.5f) * sh;
    return 1;
}

static int r6Resolve() {
    g_base = modBase("eboot.bin");
    if (!g_base) { klog("[27] eboot non trovato"); return 0; }
    uint64_t a = resolveSig("eboot.bin", SIG_GM, 3);
    uint64_t b = resolveSig("eboot.bin", SIG_LIST, 3);
    g_gm = a ? a - 4 : g_base + OF_GAMEMANAGER;
    g_list = b ? b - 4 : g_base + OF_ENTITYLIST;
    g_cam = g_base + OF_CAMERA;
    klog("[27] base ok");
    return 1;
}

static uint64_t localPawn() {
    if (!OF_LOCALPLAYER) return 0;
    uint64_t lp = *(uint64_t*)(g_base + OF_LOCALPLAYER);
    if (!lp) return 0;
    return *(uint64_t*)(lp + OF_ENT_PAWN);
}

static void r6Update() {
    g_count = 0;
    if (!OF_LOCALPLAYER || !OF_CAMERA || !OF_VIEWMATRIX) return;
    uint64_t vm = g_base + OF_VIEWMATRIX;
    for (int i = 0; i < 16; i++) g_vm[i] = *(float*)(vm + i * 4);
    uint64_t list = g_list ? *(uint64_t*)g_list : 0;
    uint64_t me = localPawn();
    if (!list || !me) return;
    Vec3 mp = *(Vec3*)(me + OF_PAWN_POS);
    int mt = *(int*)(me + OF_PAWN_TEAM);
    for (int i = 0; i < 32; i++) {
        uint64_t e = *(uint64_t*)(list + i * 8);
        if (!e) continue;
        uint64_t p = *(uint64_t*)(e + OF_ENT_PAWN);
        if (!p || p == me) continue;
        if (*(int*)(p + OF_PAWN_TEAM) == mt) continue;
        float hp = *(float*)(p + OF_PAWN_HP);
        if (hp <= 0.f) continue;
        R6Player& o = g_pl[g_count];
        o.pawn = p; o.hp = hp;
        o.pos = *(Vec3*)(p + OF_PAWN_POS);
        float dx = o.pos.x - mp.x, dy = o.pos.y - mp.y, dz = o.pos.z - mp.z;
        o.dist = sqrtf(dx * dx + dy * dy + dz * dz);
        uint64_t bn = *(uint64_t*)(p + OF_PAWN_BONES);
        if (bn) for (int k = 0; k < BONES; k++) o.bones[k] = *(Vec3*)(bn + k * 12);
        if (++g_count >= 32) break;
    }
}

static R6Player* best(int fov, int sw, int sh, float* ox, float* oy) {
    R6Player* b = 0;
    float bd = (float)(fov * fov);
    for (int i = 0; i < g_count; i++) {
        float sx, sy;
        if (!w2s(g_pl[i].bones[0].x ? g_pl[i].bones[0] : g_pl[i].pos, &sx, &sy, sw, sh)) continue;
        float dx = sx - sw * 0.5f, dy = sy - sh * 0.5f;
        float d = dx * dx + dy * dy;
        if (d < bd) { bd = d; b = &g_pl[i]; *ox = sx; *oy = sy; }
    }
    return b;
}

static void r6Aim() {
    if (!g_cfg.aimbot || !g_count || !OF_CAMERA) return;
    uint64_t cam = *(uint64_t*)g_cam;
    if (!cam) return;
    float sx, sy;
    if (!best(g_cfg.aimFov, 1920, 1080, &sx, &sy)) return;
    float yaw = *(float*)(cam + OF_CAM_YAW);
    float pit = *(float*)(cam + OF_CAM_PITCH);
    float st = 1.f / (float)(g_cfg.smooth < 1 ? 1 : g_cfg.smooth);
    *(float*)(cam + OF_CAM_YAW) = yaw - atan2f(sx - 960.f, 900.f) * 57.2958f * st;
    *(float*)(cam + OF_CAM_PITCH) = pit + atan2f(sy - 540.f, 900.f) * 57.2958f * st;
}

static void r6Silent() {
    if (!g_cfg.silent || !g_count || !OF_CAMERA) return;
    uint64_t cam = *(uint64_t*)g_cam;
    if (!cam) return;
    float sx, sy;
    if (!best(g_cfg.silFov, 1920, 1080, &sx, &sy)) return;
    *(float*)(cam + OF_CAM_YAW) -= atan2f(sx - 960.f, 900.f) * 57.2958f;
    *(float*)(cam + OF_CAM_PITCH) += atan2f(sy - 540.f, 900.f) * 57.2958f;
}

static void r6Esp(int sw, int sh) {
    if (!g_cfg.esp) return;
    static const int pr[][2] = {
        {0,1},{1,2},{2,3},{3,4},{4,5},{5,6},{4,7},{7,8},{8,9},
        {4,10},{10,11},{11,12},{4,13},{13,14},{14,15}
    };
    for (int i = 0; i < g_count; i++) {
        if (g_cfg.espDist > 0 && g_pl[i].dist > (float)g_cfg.espDist) continue;
        float px[BONES], py[BONES]; int ok[BONES];
        for (int b = 0; b < BONES; b++)
            ok[b] = w2s(g_pl[i].bones[b], &px[b], &py[b], sw, sh);
        for (int k = 0; k < 15; k++)
            if (ok[pr[k][0]] && ok[pr[k][1]])
                ovLine((int)px[pr[k][0]], (int)py[pr[k][0]],
                       (int)px[pr[k][1]], (int)py[pr[k][1]], C_RED);
        float hx, hy;
        if (w2s(g_pl[i].bones[0], &hx, &hy, sw, sh)) {
            char b[24]; snprintf(b, sizeof b, "%dM", (int)g_pl[i].dist);
            ovText((int)hx + 8, (int)hy - 10, b, C_WHITE, 1);
        }
    }
}

// ================= MENU =================
enum { T_BOOL, T_INT };
struct Item { const char* label; int type; int* b; int* i; int lo, hi, st; };
static Item ITEMS[] = {
    { "AIMBOT",        T_BOOL, &g_cfg.aimbot,   0,             0,   0,  0 },
    { "AIMBOT FOV",    T_INT,  0,               &g_cfg.aimFov, 1,  30,  1 },
    { "AIMBOT SMOOTH", T_INT,  0,               &g_cfg.smooth, 1,  20,  1 },
    { "SILENT AIM",    T_BOOL, &g_cfg.silent,   0,             0,   0,  0 },
    { "SILENT FOV",    T_INT,  0,               &g_cfg.silFov, 1,  30,  1 },
    { "SKELETON ESP",  T_BOOL, &g_cfg.esp,      0,             0,   0,  0 },
    { "ESP DIST",      T_INT,  0,               &g_cfg.espDist,0, 250, 10 },
    { "NO RECOIL",     T_BOOL, &g_cfg.norecoil, 0,             0,   0,  0 },
};
static const int NITEMS = 8;
static int g_open, g_sel;

static void menuDraw(int sw, int sh) {
    const int W = 330, RH = 26, PAD = 14;
    const int H = PAD * 2 + 46 + NITEMS * RH + 26;
    int x = (sw - W) / 2, y = (sh - H) / 2;
    ovRect(x - 2, y - 2, W + 4, H + 4, C_RED);
    ovRect(x, y, W, H, C_BG);
    ovRect(x, y, W, 42, C_BLACK);
    ovText(x + PAD, y + 11, MM_NAME, C_RED, 2);
    ovText(x + W - PAD - ovTextW("V" MM_VER, 1), y + 17, "V" MM_VER, C_DRED, 1);
    ovLine(x, y + 42, x + W, y + 42, C_RED);
    int cy = y + 42 + PAD;
    for (int i = 0; i < NITEMS; i++, cy += RH) {
        Item& it = ITEMS[i];
        int sel = (i == g_sel);
        if (sel) {
            ovRect(x + 6, cy - 4, W - 12, RH - 4, C_DRED);
            ovRect(x + 6, cy - 4, 3, RH - 4, C_RED);
        }
        ovText(x + PAD + 8, cy + 5, it.label, sel ? C_WHITE : C_RED, 1);
        char r[8];
        if (it.type == T_BOOL) snprintf(r, sizeof r, "%s", *it.b ? "ON" : "OFF");
        else snprintf(r, sizeof r, "%d", *it.i);
        ovText(x + W - PAD - ovTextW(r, 1), cy + 5, r, C_WHITE, 1);
    }
    ovLine(x, y + H - 24, x + W, y + H - 24, C_RED);
    ovText(x + PAD, y + H - 18, "X SELEZIONA  O CHIUDI", C_DRED, 1);
}

void frameRender() {
    int sw = (int)g_cw, sh = (int)g_ch;
    r6Update();
    r6Esp(sw, sh);
    if (g_open) menuDraw(sw, sh);
}

// ================= INPUT =================
static volatile int g_alive;
static uint64_t g_lastTap;

static void* inputLoop(void*) {
    int pad = -1, uid = 0;
    uint32_t prev = 0;
    while (g_alive) {
        if (pad < 0) {
            if (sceUserServiceGetForegroundUser(&uid) == 0)
                pad = scePadOpen(uid, ORBIS_PAD_PORT_TYPE_STANDARD, 0, 0);
            sceKernelUsleep(400000);
            continue;
        }
        OrbisPadData d; memset(&d, 0, sizeof d);
        if (scePadReadState(pad, &d) != 0) { scePadClose(pad); pad = -1; continue; }
        uint32_t pr = d.buttons & ~prev;
        prev = d.buttons;

        if (pr & ORBIS_PAD_BUTTON_TOUCH_PAD) {
            uint64_t now = sceKernelGetProcessTime();
            if (now - g_lastTap < (uint64_t)DBL_MS * 1000) { g_open = !g_open; g_sel = 0; g_lastTap = 0; }
            else g_lastTap = now;
        }

        if (g_open) {
            if (pr & ORBIS_PAD_BUTTON_UP) g_sel = (g_sel + NITEMS - 1) % NITEMS;
            if (pr & ORBIS_PAD_BUTTON_DOWN) g_sel = (g_sel + 1) % NITEMS;
            if (pr & ORBIS_PAD_BUTTON_LEFT) {
                Item& it = ITEMS[g_sel];
                if (it.type == T_INT) *it.i = (*it.i - it.st > it.lo) ? *it.i - it.st : it.lo;
            }
            if (pr & ORBIS_PAD_BUTTON_RIGHT) {
                Item& it = ITEMS[g_sel];
                if (it.type == T_INT) *it.i = (*it.i + it.st < it.hi) ? *it.i + it.st : it.hi;
            }
            if (pr & ORBIS_PAD_BUTTON_CROSS) {
                Item& it = ITEMS[g_sel];
                if (it.type == T_BOOL) *it.b = !*it.b;
            }
            if (pr & ORBIS_PAD_BUTTON_CIRCLE) g_open = 0;
        } else {
            if (d.buttons & ORBIS_PAD_BUTTON_R2) r6Silent();
            if (d.buttons & ORBIS_PAD_BUTTON_L2) {
                r6Aim();
                if (g_cfg.norecoil && g_count && OF_CAMERA) {
                    uint64_t cam = *(uint64_t*)g_cam;
                    if (cam) *(float*)(cam + OF_CAM_PITCH) -= 0.35f;
                }
            }
        }
        sceKernelUsleep(POLL_MS * 1000);
    }
    if (pad >= 0) scePadClose(pad);
    return 0;
}

// ================= MAIN =================
__attribute__((visibility("default"))) int _init(void) {
    OrbisUserServiceInitializeParams up; memset(&up, 0, sizeof up);
    up.priority = ORBIS_KERNEL_PRIO_FIFO_DEFAULT;
    sceUserServiceInitialize(&up);

    if (!r6Resolve()) { notify(MM_NAME ": EBOOT NON TROVATO"); return 0; }
    if (!ovInit()) { notify(MM_NAME ": VIDEO OUT FALLITO"); return 0; }

    g_alive = 1;
    OrbisPthread th;
    OrbisPthreadCreate(&th, 0, inputLoop, 0);

    notify(MM_NAME " " MM_VER " PRONTO - DOPPIO TAP TOUCHPAD");
    return 0;
}

__attribute__((visibility("default"))) void _fini(void) {
    g_alive = 0;
    sceKernelUsleep(200000);
}
