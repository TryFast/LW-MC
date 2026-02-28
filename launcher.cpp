/*
 * Compile: g++ -std=c++17 -O2 -o launcher.exe launcher.cpp -lwinhttp -lshell32
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winhttp.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

namespace fs = std::filesystem;

// ── JSON ──────────────────────────────────────────────────────────────────────

struct JVal {
    enum Type : uint8_t { Null, Bool, Num, Str, Arr, Obj } type = Null;
    bool        bval = false;
    double      nval = 0.0;
    std::string sval;
    std::vector<JVal>                         arr;
    std::vector<std::pair<std::string, JVal>> obj;

    inline bool is_null()   const { return type == Null; }
    inline bool is_string() const { return type == Str;  }
    inline bool is_array()  const { return type == Arr;  }
    inline bool is_object() const { return type == Obj;  }

    const JVal& operator[](const std::string& k) const {
        for (auto& p : obj) if (p.first == k) return p.second;
        static JVal nv; return nv;
    }
    JVal& operator[](const std::string& k) {
        for (auto& p : obj) if (p.first == k) return p.second;
        obj.push_back({k, JVal{}});
        return obj.back().second;
    }
    const JVal& operator[](size_t i) const { return arr[i]; }

    bool has(const std::string& k) const {
        for (auto& p : obj) if (p.first == k) return true;
        return false;
    }
    const std::string& str()  const { return sval; }
    double             num()  const { return nval; }
    size_t             size() const { return type == Arr ? arr.size() : obj.size(); }
};

namespace {

inline void skip_ws(const char*& p) {
    while ((*p == ' ') | (*p == '\t') | (*p == '\r') | (*p == '\n')) ++p;
}

std::string parse_str_tok(const char*& p) {
    ++p;
    std::string s;
    s.reserve(64);
    while (*p && *p != '"') {
        if (*p == '\\') {
            ++p;
            switch (*p) {
                case '"':  s += '"';  break;
                case '\\': s += '\\'; break;
                case '/':  s += '/';  break;
                case 'n':  s += '\n'; break;
                case 'r':  s += '\r'; break;
                case 't':  s += '\t'; break;
                default:   s += '\\'; s += *p; break;
            }
        } else {
            s += *p;
        }
        ++p;
    }
    if (*p == '"') ++p;
    return s;
}

JVal parse_val(const char*& p);

JVal parse_obj(const char*& p) {
    JVal v; v.type = JVal::Obj;
    ++p;
    for (;;) {
        skip_ws(p);
        if (!*p || *p == '}') break;
        if (*p != '"') break;
        std::string key = parse_str_tok(p);
        skip_ws(p);
        if (*p == ':') ++p;
        v.obj.push_back({std::move(key), parse_val(p)});
        skip_ws(p);
        if (*p == ',') ++p;
    }
    if (*p == '}') ++p;
    return v;
}

JVal parse_arr(const char*& p) {
    JVal v; v.type = JVal::Arr;
    ++p;
    for (;;) {
        skip_ws(p);
        if (!*p || *p == ']') break;
        v.arr.push_back(parse_val(p));
        skip_ws(p);
        if (*p == ',') ++p;
    }
    if (*p == ']') ++p;
    return v;
}

JVal parse_val(const char*& p) {
    skip_ws(p);
    switch (*p) {
        case '{': return parse_obj(p);
        case '[': return parse_arr(p);
        case '"': { JVal v; v.type = JVal::Str; v.sval = parse_str_tok(p); return v; }
        case 't': if (!strncmp(p,"true", 4)) { JVal v; v.type=JVal::Bool; v.bval=true;  p+=4; return v; } break;
        case 'f': if (!strncmp(p,"false",5)) { JVal v; v.type=JVal::Bool; v.bval=false; p+=5; return v; } break;
        case 'n': if (!strncmp(p,"null", 4)) { p+=4; return JVal{}; } break;
    }
    char* end;
    JVal v; v.type = JVal::Num; v.nval = strtod(p, &end); p = end;
    return v;
}

JVal parse_json(const std::string& src) {
    const char* p = src.c_str();
    return parse_val(p);
}

// ── WinHTTP ───────────────────────────────────────────────────────────────────

inline std::wstring to_wide(const char* s, int len = -1) {
    if (!s || !*s) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s, len, nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, len, w.data(), n);
    return w;
}
inline std::wstring to_wide(const std::string& s) { return to_wide(s.c_str(), (int)s.size()); }

inline std::string to_utf8(const wchar_t* w, int len = -1) {
    if (!w || !*w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, len, s.data(), n, nullptr, nullptr);
    return s;
}

struct WSession {
    HINTERNET h = nullptr;
    WSession() {
        h = WinHttpOpen(L"MCLauncher/2.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (h) {
            DWORD pol = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            WinHttpSetOption(h, WINHTTP_OPTION_REDIRECT_POLICY, &pol, sizeof(pol));
        }
    }
    ~WSession() { if (h) WinHttpCloseHandle(h); }
    WSession(const WSession&) = delete;
    WSession& operator=(const WSession&) = delete;
} g_sess;

struct CrackResult { std::wstring host, path; INTERNET_PORT port; bool https; };

CrackResult crack_url(const std::wstring& url) {
    CrackResult r{};
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[512]{}, path[4096]{};
    uc.lpszHostName = host; uc.dwHostNameLength = 512;
    uc.lpszUrlPath  = path; uc.dwUrlPathLength  = 4096;
    WinHttpCrackUrl(url.c_str(), 0, 0, &uc);
    r.host  = host;
    r.path  = path;
    r.port  = uc.nPort;
    r.https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    return r;
}

// Opens a GET request following up to max_redir redirects.
// Caller must close out_conn and returned handle on success.
HINTERNET open_req(const std::string& url_s, HINTERNET& out_conn, int max_redir = 10) {
    if (!g_sess.h) return nullptr;
    std::string cur = url_s;

    for (int i = 0; i <= max_redir; ++i) {
        auto pu = crack_url(to_wide(cur));

        HINTERNET hConn = WinHttpConnect(g_sess.h, pu.host.c_str(), pu.port, 0);
        if (!hConn) return nullptr;

        DWORD flags = pu.https ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", pu.path.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hReq) { WinHttpCloseHandle(hConn); return nullptr; }

        if (pu.https) {
            DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
            WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));
        }

        if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(hReq, nullptr)) {
            WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
            return nullptr;
        }

        DWORD status = 0, sz = sizeof(status);
        WinHttpQueryHeaders(hReq,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);

        if (status == 301 || status == 302 || status == 303 ||
            status == 307 || status == 308) {
            DWORD loc_sz = 0;
            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION,
                WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &loc_sz, WINHTTP_NO_HEADER_INDEX);
            if (loc_sz > 0) {
                std::wstring loc(loc_sz / sizeof(wchar_t) + 1, L'\0');
                WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION,
                    WINHTTP_HEADER_NAME_BY_INDEX, loc.data(), &loc_sz, WINHTTP_NO_HEADER_INDEX);
                while (!loc.empty() && loc.back() == L'\0') loc.pop_back();
                cur = to_utf8(loc.c_str());
            }
            WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
            continue;
        }

        out_conn = hConn;
        return hReq;
    }
    return nullptr;
}

std::string http_get_str(const std::string& url) {
    HINTERNET hConn = nullptr;
    HINTERNET hReq  = open_req(url, hConn);
    if (!hReq) return {};

    std::string result;
    result.reserve(65536);
    char buf[8192];
    DWORD read = 0;
    while (WinHttpReadData(hReq, buf, sizeof(buf), &read) && read) result.append(buf, read);

    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
    return result;
}

// Streams response directly to file — no full-body allocation.
// Critical for large downloads (JDK zips, client JARs).
bool http_download(const std::string& url, const fs::path& dest) {
    HINTERNET hConn = nullptr;
    HINTERNET hReq  = open_req(url, hConn);
    if (!hReq) return false;

    fs::create_directories(dest.parent_path());

    HANDLE hFile = CreateFileW(dest.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
        return false;
    }

    bool ok = true;
    char buf[65536];
    DWORD read = 0, written = 0;
    while (WinHttpReadData(hReq, buf, sizeof(buf), &read) && read) {
        if (!WriteFile(hFile, buf, read, &written, nullptr) || written != read) { ok = false; break; }
    }

    CloseHandle(hFile);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
    if (!ok) fs::remove(dest);
    return ok;
}

// ── Config ────────────────────────────────────────────────────────────────────

struct Config {
    std::string username  = "Player";
    std::string java_path = "java";
    int         ram_gb    = 2;
};

inline std::string esc_json(const std::string& s) {
    std::string r;
    r.reserve(s.size() + 4);
    for (char c : s) {
        if      (c == '"')  r += "\\\"";
        else if (c == '\\') r += "\\\\";
        else r += c;
    }
    return r;
}

Config load_config(const fs::path& p) {
    Config c;
    if (!fs::exists(p)) return c;
    std::ifstream f(p);
    std::string s((std::istreambuf_iterator<char>(f)), {});
    auto j = parse_json(s);
    if (j.has("username"))  c.username  = j["username"].str();
    if (j.has("java_path")) c.java_path = j["java_path"].str();
    if (j.has("ram_gb"))    c.ram_gb    = (int)j["ram_gb"].num();
    if (c.ram_gb < 1) c.ram_gb = 1;
    return c;
}

void save_config(const Config& c, const fs::path& p) {
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "{\n  \"username\": \"%s\",\n  \"java_path\": \"%s\",\n  \"ram_gb\": %d\n}\n",
        esc_json(c.username).c_str(), esc_json(c.java_path).c_str(), c.ram_gb);
    if (n > 0) { std::ofstream f(p); f.write(buf, n); }
}

inline bool check_java(const std::string& java) {
    return system(("\"" + java + "\" -version > NUL 2>&1").c_str()) == 0;
}

// ── Version helpers ───────────────────────────────────────────────────────────

struct MCVer { int v[3] = {}; };

MCVer parse_mc_ver(const std::string& s) {
    MCVer r{};
    int idx = 0;
    const char* p = s.c_str();
    while (*p && idx < 3) {
        if (!isdigit((uint8_t)*p)) { if (*p != '.') break; ++p; continue; }
        while (isdigit((uint8_t)*p)) r.v[idx] = r.v[idx] * 10 + (*p++ - '0');
        if (++idx < 3 && *p == '.') ++p;
    }
    return r;
}

inline int cmp_ver(const MCVer& a, const MCVer& b) {
    for (int i = 0; i < 3; ++i) {
        if (a.v[i] < b.v[i]) return -1;
        if (a.v[i] > b.v[i]) return  1;
    }
    return 0;
}

inline int required_jdk(const std::string& mc) {
    static const MCVer v117 = parse_mc_ver("1.17");
    static const MCVer v121 = parse_mc_ver("1.21");
    MCVer v = parse_mc_ver(mc);
    if (cmp_ver(v, v117) < 0) return 8;
    if (cmp_ver(v, v121) < 0) return 17;
    return 21;
}

// ── Minecraft helpers ─────────────────────────────────────────────────────────

std::string make_offline_uuid(const std::string& name) {
    std::string seed = "OfflinePlayer:" + name;
    uint8_t h[16]{};
    for (size_t i = 0; i < seed.size(); ++i) {
        h[i % 16]     ^= (uint8_t)(seed[i] * (i + 1));
        h[(i+3) % 16] += (uint8_t)seed[i];
    }
    h[6] = (h[6] & 0x0f) | 0x30;
    h[8] = (h[8] & 0x3f) | 0x80;
    char buf[37];
    snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7],
        h[8],h[9],h[10],h[11],h[12],h[13],h[14],h[15]);
    return buf;
}

inline bool lib_applies(const JVal& lib) {
    if (!lib.has("rules")) return true;
    bool allowed = false;
    for (size_t i = 0; i < lib["rules"].size(); ++i) {
        const auto& rule = lib["rules"].arr[i];
        bool match = !rule.has("os") || rule["os"]["name"].str() == "windows";
        if (match) allowed = (rule["action"].str() == "allow");
    }
    return allowed;
}

std::string find_java_in_dir(const fs::path& dir) {
    if (!fs::exists(dir)) return {};
    std::error_code ec;
    for (auto& e : fs::recursive_directory_iterator(dir, ec)) {
        if (!e.is_regular_file(ec)) continue;
        auto fn = e.path().filename().string();
        std::transform(fn.begin(), fn.end(), fn.begin(), ::tolower);
        if (fn == "javaw.exe") return e.path().string();
    }
    return {};
}

bool download_file(const std::string& url, const fs::path& dest) {
    if (fs::exists(dest) && fs::file_size(dest) > 0) return true;
    if (!http_download(url, dest)) {
        fprintf(stderr, "  [FAIL] %s\n", dest.filename().string().c_str());
        return false;
    }
    return true;
}

static const char* MANIFEST_URL  = "https://launchermeta.mojang.com/mc/game/version_manifest.json";
static const char* RESOURCES_URL = "https://resources.download.minecraft.net/";

// ── JDK install ───────────────────────────────────────────────────────────────

std::string get_adoptium_url(int jdk) {
    std::string api = "https://api.adoptium.net/v3/assets/latest/" +
                      std::to_string(jdk) +
                      "/hotspot?architecture=x64&image_type=jdk&os=windows";
    printf("  Querying Adoptium API for JDK %d...\n", jdk);
    std::string resp = http_get_str(api);
    if (resp.empty()) { fputs("  Adoptium API unreachable.\n", stderr); return {}; }
    auto j = parse_json(resp);
    if (!j.is_array() || !j.size()) { fputs("  No packages in response.\n", stderr); return {}; }
    for (size_t i = 0; i < j.size(); ++i) {
        const auto& pkg  = j[i]["binary"]["package"];
        const auto& name = pkg["name"].str();
        if (name.size() >= 4 && name.compare(name.size()-4, 4, ".zip") == 0) {
            const auto& url = pkg["link"].str();
            if (!url.empty()) return url;
        }
    }
    fputs("  No .zip in Adoptium response.\n", stderr);
    return {};
}

bool install_bundled_jre(const fs::path& root, Config& cfg, const fs::path& cfg_path,
                         const std::string& mc_ver = "") {
    int jdk = mc_ver.empty() ? 8 : required_jdk(mc_ver);
    fs::path jdk_dir = root / ("jdk" + std::to_string(jdk));

    std::string existing = find_java_in_dir(jdk_dir);
    if (!existing.empty()) {
        printf("  Found Temurin JDK %d: %s\n", jdk, existing.c_str());
        cfg.java_path = existing;
        save_config(cfg, cfg_path);
        return true;
    }

    printf("\nRequires Java %d. No bundled JDK in: %s\n", jdk, jdk_dir.string().c_str());
    printf("Download Eclipse Adoptium Temurin JDK %d automatically? (y/n): ", jdk);
    std::string ans;
    std::getline(std::cin, ans);
    if (ans.empty() || (ans[0] != 'y' && ans[0] != 'Y')) return false;

    std::string dl_url = get_adoptium_url(jdk);
    if (dl_url.empty()) return false;

    std::string zip_name = dl_url.substr(dl_url.rfind('/') + 1);
    if (zip_name.empty()) zip_name = "temurin-jdk" + std::to_string(jdk) + ".zip";
    fs::path zip_dest = root / zip_name;

    printf("  Downloading: %s\n", dl_url.c_str());
    if (!download_file(dl_url, zip_dest)) { fputs("  Download failed.\n", stderr); return false; }

    printf("  Extracting to: %s\n", jdk_dir.string().c_str());
    fs::create_directories(jdk_dir);

    std::string cmd = "powershell -NoProfile -Command \"Expand-Archive -Force -LiteralPath '"
                    + zip_dest.string() + "' -DestinationPath '" + jdk_dir.string() + "'\"";
    int ret = system(cmd.c_str());
    if (ret != 0) { fprintf(stderr, "  Extraction failed (exit %d).\n", ret); return false; }

    std::error_code ec;
    fs::remove(zip_dest, ec);

    std::string found = find_java_in_dir(jdk_dir);
    if (found.empty()) { fprintf(stderr, "javaw.exe not found in jdk%d after extraction.\n", jdk); return false; }

    printf("Temurin JDK %d installed: %s\n", jdk, found.c_str());
    cfg.java_path = found;
    save_config(cfg, cfg_path);
    return true;
}

// ── Download ──────────────────────────────────────────────────────────────────

JVal fetch_manifest() {
    fputs("Fetching version manifest...\n", stdout);
    std::string s = http_get_str(MANIFEST_URL);
    if (s.empty()) { fputs("Failed to fetch manifest.\n", stderr); return {}; }
    return parse_json(s);
}

bool download_minecraft(const fs::path& root, const std::string& version) {
    auto manifest = fetch_manifest();
    if (manifest.is_null()) return false;

    std::string ver_url;
    for (size_t i = 0; i < manifest["versions"].size(); ++i) {
        const auto& v = manifest["versions"].arr[i];
        if (v["id"].str() == version) { ver_url = v["url"].str(); break; }
    }
    if (ver_url.empty()) { fprintf(stderr, "Version %s not found.\n", version.c_str()); return false; }

    fs::path ver_dir  = root / "versions" / version;
    fs::path ver_json = ver_dir / (version + ".json");
    fs::path ver_jar  = ver_dir / (version + ".jar");
    fs::create_directories(ver_dir);

    printf("[2/5] Fetching %s version JSON...\n", version.c_str());
    std::string ver_str;
    if (fs::exists(ver_json)) {
        std::ifstream f(ver_json);
        ver_str.assign(std::istreambuf_iterator<char>(f), {});
    } else {
        ver_str = http_get_str(ver_url);
        if (ver_str.empty()) { fputs("Failed to fetch version JSON.\n", stderr); return false; }
        std::ofstream f(ver_json); f << ver_str;
    }
    auto vj = parse_json(ver_str);

    fputs("[3/5] Downloading client JAR...\n", stdout);
    if (!download_file(vj["downloads"]["client"]["url"].str(), ver_jar)) {
        fputs("Failed to download client JAR.\n", stderr); return false;
    }

    fputs("[4/5] Downloading libraries...\n", stdout);
    fs::path lib_dir = root / "libraries";
    for (size_t i = 0; i < vj["libraries"].size(); ++i) {
        const auto& lib = vj["libraries"].arr[i];
        if (!lib_applies(lib)) continue;

        bool is_native = false;
        std::string nat_cls;
        if (lib.has("natives") && lib["natives"].has("windows")) {
            nat_cls = lib["natives"]["windows"].str();
            const char* arch = sizeof(void*) == 8 ? "64" : "32";
            size_t pos = nat_cls.find("${arch}");
            if (pos != std::string::npos) nat_cls.replace(pos, 7, arch);
            is_native = true;
        }

        auto try_dl = [&](const std::string& cls) {
            if (!lib.has("downloads")) return;
            const JVal* art = nullptr;
            if (!cls.empty()) {
                if (lib["downloads"].has("classifiers") && lib["downloads"]["classifiers"].has(cls))
                    art = &lib["downloads"]["classifiers"][cls];
            } else if (lib["downloads"].has("artifact")) {
                art = &lib["downloads"]["artifact"];
            }
            if (!art || art->is_null()) return;
            const auto& u = (*art)["url"].str();
            const auto& p = (*art)["path"].str();
            if (u.empty() || p.empty()) return;
            fs::path dest = lib_dir / p;
            if (download_file(u, dest)) {
                printf("  + %s\n", p.c_str());
                if (is_native) {
                    fs::path nat_dir = root / "natives";
                    fs::create_directories(nat_dir);
                    system(("tar -xf \"" + dest.string() + "\" -C \"" + nat_dir.string() + "\" --exclude=META-INF 2>NUL").c_str());
                }
            } else {
                fprintf(stderr, "  warn: failed %s\n", p.c_str());
            }
        };

        if (is_native) try_dl(nat_cls);
        try_dl({});
    }

    fputs("[5/5] Downloading assets...\n", stdout);
    const auto& idx_url = vj["assetIndex"]["url"].str();
    const auto& idx_id  = vj["assetIndex"]["id"].str();
    fs::path idx_file   = root / "assets" / "indexes" / (idx_id + ".json");
    fs::create_directories(idx_file.parent_path());

    std::string idx_str;
    if (fs::exists(idx_file)) {
        std::ifstream f(idx_file);
        idx_str.assign(std::istreambuf_iterator<char>(f), {});
    } else {
        idx_str = http_get_str(idx_url);
        if (idx_str.empty()) { fputs("Failed to fetch asset index.\n", stderr); return false; }
        std::ofstream f(idx_file); f << idx_str;
    }

    const auto& objs = parse_json(idx_str)["objects"];
    size_t total = objs.size(), done = 0;
    for (const auto& kv : objs.obj) {
        const auto& hash = kv.second["hash"].str();
        std::string pfx  = hash.substr(0, 2);
        fs::path dest    = root / "assets" / "objects" / pfx / hash;
        if (!fs::exists(dest) || !fs::file_size(dest))
            download_file(std::string(RESOURCES_URL) + pfx + "/" + hash, dest);
        ++done;
        if (done % 50 == 0 || done == total)
            printf("  Assets: %zu/%zu\r", done, total);
    }
    putchar('\n');
    return true;
}

// ── Launch ────────────────────────────────────────────────────────────────────

std::string build_classpath(const fs::path& root, const JVal& vj, const std::string& version) {
    std::string cp;
    cp.reserve(4096);
    fs::path lib_dir = root / "libraries";
    for (size_t i = 0; i < vj["libraries"].size(); ++i) {
        const auto& lib = vj["libraries"].arr[i];
        if (!lib_applies(lib)) continue;
        if (lib.has("natives") && lib["natives"].has("windows")) continue;
        if (!lib.has("downloads") || !lib["downloads"].has("artifact")) continue;
        const auto& p = lib["downloads"]["artifact"]["path"].str();
        if (p.empty()) continue;
        fs::path jar = lib_dir / p;
        if (fs::exists(jar)) { cp += jar.string(); cp += ';'; }
    }
    cp += (root / "versions" / version / (version + ".jar")).string();
    return cp;
}

using VarMap = std::unordered_map<std::string, std::string>;

std::string tok_replace(const std::string& s, const VarMap& m) {
    std::string r;
    r.reserve(s.size() + 32);
    for (size_t i = 0; i < s.size(); ) {
        if (s[i] == '$' && i+1 < s.size() && s[i+1] == '{') {
            size_t e = s.find('}', i+2);
            if (e != std::string::npos) {
                auto it = m.find(s.substr(i+2, e-i-2));
                r += it != m.end() ? it->second : s.substr(i, e-i+1);
                i = e+1; continue;
            }
        }
        r += s[i++];
    }
    return r;
}

std::string win_quote(const std::string& s) {
    if (s.find_first_of(" \t\"") == std::string::npos && !s.empty()) return s;
    std::string r;
    r.reserve(s.size() + 8);
    r += '"';
    int sl = 0;
    for (char c : s) {
        if      (c == '\\') { ++sl; }
        else if (c == '"')  { r.append(sl*2+1,'\\'); r += '"'; sl = 0; }
        else                { if (sl) { r.append(sl,'\\'); sl=0; } r += c; }
    }
    if (sl) r.append(sl*2, '\\');
    r += '"';
    return r;
}

bool launch_version(const fs::path& root, const Config& cfg, const std::string& version) {
    fs::path vj_path = root / "versions" / version / (version + ".json");
    if (!fs::exists(vj_path)) { fprintf(stderr, "Not installed: %s\n", version.c_str()); return false; }

    std::ifstream f(vj_path);
    auto vj = parse_json(std::string(std::istreambuf_iterator<char>(f), {}));

    std::string cp        = build_classpath(root, vj, version);
    std::string uuid      = make_offline_uuid(cfg.username);
    std::string nat       = (root / "natives").string();
    std::string assets    = (root / "assets").string();
    std::string asset_idx = vj["assetIndex"]["id"].str();
    std::string game_dir  = root.string();
    std::string ver_type  = vj.has("type") ? vj["type"].str() : "release";
    std::string main_cls  = vj["mainClass"].str();
    if (main_cls.empty()) main_cls = "net.minecraft.client.main.Main";

    VarMap vars = {
        {"auth_player_name",  cfg.username},
        {"auth_uuid",         uuid},
        {"auth_access_token", "0"},
        {"user_type",         "legacy"},
        {"user_properties",   "{}"},
        {"version_name",      version},
        {"version_type",      ver_type},
        {"game_directory",    game_dir},
        {"assets_root",       assets},
        {"game_assets",       assets},
        {"assets_index_name", asset_idx},
        {"natives_directory", nat},
        {"classpath",         cp},
        {"launcher_name",     "MCLauncher"},
        {"launcher_version",  "2.0"},
    };

    std::vector<std::string> args;
    args.reserve(32);
    args.push_back("-Xmx" + std::to_string(cfg.ram_gb) + "G");
    args.push_back("-Xms512m");

    if (required_jdk(version) <= 8) {
        args.push_back("-XX:+UseConcMarkSweepGC");
        args.push_back("-XX:+CMSIncrementalMode");
    } else {
        args.insert(args.end(), {
            "-XX:+UseG1GC", "-XX:+UnlockExperimentalVMOptions",
            "-XX:G1NewSizePercent=20", "-XX:G1ReservePercent=20",
            "-XX:MaxGCPauseMillis=50", "-XX:G1HeapRegionSize=32M"
        });
    }

    if (vj.has("arguments")) {
        auto collect = [&](const JVal& arr, std::vector<std::string>& out) {
            for (size_t i = 0; i < arr.size(); ++i) {
                const auto& e = arr.arr[i];
                if (e.is_string()) { out.push_back(tok_replace(e.str(), vars)); continue; }
                if (!e.is_object()) continue;
                bool ok = true;
                if (e.has("rules")) {
                    ok = false;
                    for (size_t r = 0; r < e["rules"].size(); ++r) {
                        const auto& rule = e["rules"].arr[r];
                        bool match = !rule.has("os") || rule["os"]["name"].str() == "windows";
                        if (rule.has("features")) match = false;
                        if (match) ok = (rule["action"].str() == "allow");
                    }
                }
                if (!ok) continue;
                const auto& val = e["value"];
                if (val.is_string()) out.push_back(tok_replace(val.str(), vars));
                else if (val.is_array())
                    for (size_t j = 0; j < val.size(); ++j)
                        out.push_back(tok_replace(val.arr[j].str(), vars));
            }
        };
        std::vector<std::string> jvm_a, game_a;
        collect(vj["arguments"]["jvm"],  jvm_a);
        collect(vj["arguments"]["game"], game_a);
        for (auto& a : jvm_a)  args.push_back(a);
        args.push_back(main_cls);
        for (auto& a : game_a) args.push_back(a);
    } else {
        args.push_back("-Djava.library.path=" + nat);
        args.push_back("-Dfile.encoding=UTF-8");
        args.push_back("-cp");
        args.push_back(cp);
        args.push_back(main_cls);
        const auto& mc_args = vj["minecraftArguments"].str();
        for (size_t s = 0, e; s < mc_args.size(); s = e+1) {
            e = mc_args.find(' ', s);
            if (e == std::string::npos) { args.push_back(tok_replace(mc_args.substr(s), vars)); break; }
            args.push_back(tok_replace(mc_args.substr(s, e-s), vars));
        }
    }

    std::string cmd;
    cmd.reserve(2048);
    cmd = win_quote(cfg.java_path);
    for (auto& a : args) { cmd += ' '; cmd += win_quote(a); }

    printf("\nLaunching Minecraft %s as %s...\n[CMD] %s\n\n",
           version.c_str(), cfg.username.c_str(), cmd.c_str());

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring wcmd = to_wide(cmd);
    wcmd += L'\0';

    if (!CreateProcessW(nullptr, wcmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NEW_CONSOLE, nullptr,
                        to_wide(game_dir).c_str(), &si, &pi)) {
        fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

std::vector<std::string> get_installed_versions(const fs::path& root) {
    std::vector<std::string> v;
    fs::path ver_dir = root / "versions";
    if (!fs::exists(ver_dir)) return v;
    std::error_code ec;
    for (auto& e : fs::directory_iterator(ver_dir, ec)) {
        if (!e.is_directory(ec)) continue;
        std::string name = e.path().filename().string();
        fs::path jar = e.path() / (name + ".jar");
        if (fs::exists(jar) && fs::file_size(jar) > 1024) v.push_back(name);
    }
    std::sort(v.begin(), v.end());
    return v;
}

void print_header(const char* title) {
    printf("\n================================================\n  %s\n================================================\n", title);
}

void section_download(const fs::path& root, Config& cfg, const fs::path& cfg_path) {
    print_header("DOWNLOAD");

    auto manifest = fetch_manifest();
    if (manifest.is_null()) { fputs("Press Enter to continue...", stdout); std::cin.get(); return; }

    struct VE { std::string id, type; };
    std::vector<VE> entries;
    entries.reserve(manifest["versions"].size());
    for (size_t i = 0; i < manifest["versions"].size(); ++i) {
        const auto& v = manifest["versions"].arr[i];
        entries.push_back({v["id"].str(), v["type"].str()});
    }

    fputs("\nFilter: (1) Releases only  (2) All versions\nChoice: ", stdout);
    std::string fin;
    std::getline(std::cin, fin);
    bool releases_only = (fin != "2");

    std::vector<VE> filtered;
    filtered.reserve(entries.size());
    for (auto& e : entries)
        if (!releases_only || e.type == "release") filtered.push_back(e);

    int page = 0;
    const int PAGE = 20;
    for (;;) {
        int pages = ((int)filtered.size() + PAGE - 1) / PAGE;
        int start = page * PAGE;
        int end   = std::min(start + PAGE, (int)filtered.size());

        printf("\nVersions (page %d/%d):\n", page+1, pages);
        for (int i = start; i < end; ++i) {
            printf("  [%d] %s", i-start+1, filtered[i].id.c_str());
            if (filtered[i].type != "release") printf(" (%s)", filtered[i].type.c_str());
            putchar('\n');
        }
        fputs("\nEnter number, 'n' next, 'p' prev, 'q' cancel: ", stdout);
        std::string input;
        std::getline(std::cin, input);

        if (input == "q" || input == "Q") return;
        if (input == "n" || input == "N") { if (page+1 < pages) ++page; continue; }
        if (input == "p" || input == "P") { if (page > 0) --page; continue; }

        try {
            int idx = std::stoi(input) - 1 + start;
            if (idx < 0 || idx >= (int)filtered.size()) { fputs("Invalid selection.\n", stdout); continue; }
            const std::string& chosen = filtered[idx].id;

            fs::path jar = root / "versions" / chosen / (chosen + ".jar");
            if (fs::exists(jar) && fs::file_size(jar) > 1024) {
                printf("\nVersion %s is already installed.\n", chosen.c_str());
            } else {
                printf("\nDownload Minecraft %s? (y/n): ", chosen.c_str());
                std::string ans;
                std::getline(std::cin, ans);
                if (ans.empty() || (ans[0] != 'y' && ans[0] != 'Y')) return;
                if (!install_bundled_jre(root, cfg, cfg_path, chosen))
                    fputs("Continuing without bundled JDK.\n", stdout);
                fputs("\n[1/5] Manifest already fetched.\n", stdout);
                if (!download_minecraft(root, chosen))
                    fputs("\nDownload failed.\n", stderr);
                else
                    printf("\nDownload complete! %s is ready.\n", chosen.c_str());
            }
            fputs("Press Enter to continue...", stdout); std::cin.get();
            return;
        } catch (...) { fputs("Invalid input.\n", stdout); }
    }
}

void section_settings(Config& cfg, const fs::path& cfg_path) {
    for (;;) {
        print_header("SETTINGS");
        printf("  [1] Username   : %s\n"
               "  [2] RAM (GB)   : %dGB\n"
               "  [3] Java Path  : %s\n"
               "  [4] Back\n\nChoice: ",
               cfg.username.c_str(), cfg.ram_gb, cfg.java_path.c_str());

        std::string input;
        std::getline(std::cin, input);

        if (input == "1") {
            printf("New username [%s]: ", cfg.username.c_str());
            std::string val; std::getline(std::cin, val);
            if (!val.empty()) cfg.username = val;
        } else if (input == "2") {
            printf("RAM in GB [%d]: ", cfg.ram_gb);
            std::string val; std::getline(std::cin, val);
            try {
                int gb = std::stoi(val);
                if (gb >= 1 && gb <= 64) cfg.ram_gb = gb;
                else fputs("Invalid. Must be 1-64.\n", stdout);
            } catch (...) {}
        } else if (input == "3") {
            printf("Java path [%s]: ", cfg.java_path.c_str());
            std::string val; std::getline(std::cin, val);
            if (!val.empty()) {
                if (!check_java(val)) fputs("Warning: could not verify java at that path.\n", stdout);
                cfg.java_path = val;
            }
        } else if (input == "4" || input == "q" || input == "Q") {
            break;
        }
        save_config(cfg, cfg_path);
        fputs("Settings saved.\n", stdout);
    }
}

void section_launch(const fs::path& root, Config& cfg, const fs::path& cfg_path) {
    print_header("LAUNCH");
    auto versions = get_installed_versions(root);
    if (versions.empty()) {
        fputs("\nNo installed versions. Go to Download first.\nPress Enter to continue...", stdout);
        std::cin.get();
        return;
    }

    fputs("\nInstalled versions:\n", stdout);
    for (size_t i = 0; i < versions.size(); ++i)
        printf("  [%zu] %s\n", i+1, versions[i].c_str());
    fputs("\nSelect version (or 'q' to cancel): ", stdout);

    std::string input;
    std::getline(std::cin, input);
    if (input == "q" || input == "Q") return;

    try {
        int idx = std::stoi(input) - 1;
        if (idx < 0 || idx >= (int)versions.size()) {
            fputs("Invalid selection.\nPress Enter to continue...", stdout);
            std::cin.get();
            return;
        }
        const std::string& chosen = versions[idx];
        if (!check_java(cfg.java_path)) {
            printf("\nJava not found at: %s\nLocating bundled JDK...\n", cfg.java_path.c_str());
            if (!install_bundled_jre(root, cfg, cfg_path, chosen)) {
                fputs("Java unavailable. Set Java Path in Settings.\nPress Enter to continue...", stderr);
                std::cin.get();
                return;
            }
        }
        if (!launch_version(root, cfg, chosen)) {
            fputs("Press Enter to continue...", stdout);
            std::cin.get();
        } else {
            fputs("Game launched! Exiting launcher...\n", stdout);
            Sleep(1500);
        }
    } catch (...) {
        fputs("Invalid input.\nPress Enter to continue...", stdout);
        std::cin.get();
    }
}

} // namespace

int main() {
    SetConsoleOutputCP(CP_UTF8);

    wchar_t exe[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    fs::path root     = fs::path(exe).parent_path();
    fs::path cfg_path = root / "config.json";
    Config   cfg      = load_config(cfg_path);

    if (cfg.username.empty() || cfg.username == "Player") {
        fputs("=== Minecraft Launcher ===\n\nEnter your username: ", stdout);
        std::getline(std::cin, cfg.username);
        if (cfg.username.empty()) cfg.username = "Player";
        save_config(cfg, cfg_path);
    }

    for (;;) {
        print_header("MINECRAFT LAUNCHER");
        fputs("  [1] Download\n  [2] Settings\n  [3] Launch\n  [4] Exit\n\nChoice: ", stdout);
        std::string input;
        std::getline(std::cin, input);

        if      (input == "1") section_download(root, cfg, cfg_path);
        else if (input == "2") section_settings(cfg, cfg_path);
        else if (input == "3") section_launch(root, cfg, cfg_path);
        else if (input == "4" || input == "q" || input == "Q") break;
    }
    return 0;
}
