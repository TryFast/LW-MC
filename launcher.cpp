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
#include <thread>
#include <atomic>
#include <mutex>

#pragma comment(lib, "winhttp.lib")

namespace fs = std::filesystem;

struct JVal {
    enum Type : uint8_t { Null, Bool, Num, Str, Arr, Obj } type = Null;
    bool        bval = false;
    double      nval = 0.0;
    std::string sval;
    std::vector<JVal>                         arr;
    std::vector<std::pair<std::string, JVal>> obj;

    bool is_null()   const { return type == Null; }
    bool is_string() const { return type == Str;  }
    bool is_array()  const { return type == Arr;  }
    bool is_object() const { return type == Obj;  }

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
    JVal&       operator[](size_t i)       { return arr[i]; }

    bool has(const std::string& k) const {
        for (auto& p : obj) if (p.first == k) return true;
        return false;
    }
    const std::string& str()  const { return sval; }
    double             num()  const { return nval; }
    size_t             size() const { return type == Arr ? arr.size() : obj.size(); }
};

static inline void skip_ws(const char*& p) {
    while ((*p == ' ') | (*p == '\t') | (*p == '\r') | (*p == '\n')) ++p;
}

static std::string parse_str_tok(const char*& p) {
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

static JVal parse_val(const char*& p);

static JVal parse_obj(const char*& p) {
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

static JVal parse_arr(const char*& p) {
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

static JVal parse_val(const char*& p) {
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

static JVal parse_json(const std::string& src) {
    const char* p = src.c_str();
    return parse_val(p);
}

static inline std::wstring to_wide(const char* s, int len = -1) {
    if (!s || !*s) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s, len, nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, len, w.data(), n);
    return w;
}
static inline std::wstring to_wide(const std::string& s) { return to_wide(s.c_str(), (int)s.size()); }

static inline std::string to_utf8(const wchar_t* w, int len = -1) {
    if (!w || !*w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, len, s.data(), n, nullptr, nullptr);
    return s;
}

struct WSession {
    HINTERNET h = nullptr;
    WSession() {
        h = WinHttpOpen(L"MCLauncher/3.0",
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

static CrackResult crack_url(const std::wstring& url) {
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

static HINTERNET open_req(const std::string& url_s, HINTERNET& out_conn, int max_redir = 10) {
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

static std::string http_get_str(const std::string& url) {
    HINTERNET hConn = nullptr;
    HINTERNET hReq  = open_req(url, hConn);
    if (!hReq) return {};

    std::string result;
    result.reserve(65536);
    char buf[65536];
    DWORD read = 0;
    while (WinHttpReadData(hReq, buf, sizeof(buf), &read) && read) result.append(buf, read);

    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
    return result;
}

static std::mutex g_mkdir_mtx;

static bool http_download(const std::string& url, const fs::path& dest) {
    HINTERNET hConn = nullptr;
    HINTERNET hReq  = open_req(url, hConn);
    if (!hReq) return false;

    {
        std::lock_guard<std::mutex> lk(g_mkdir_mtx);
        fs::create_directories(dest.parent_path());
    }

    HANDLE hFile = CreateFileW(dest.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
        return false;
    }

    bool ok = true;
    char buf[131072];
    DWORD read = 0, written = 0;
    while (WinHttpReadData(hReq, buf, sizeof(buf), &read) && read) {
        if (!WriteFile(hFile, buf, read, &written, nullptr) || written != read) { ok = false; break; }
    }

    CloseHandle(hFile);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn);
    if (!ok) { std::error_code ec; fs::remove(dest, ec); }
    return ok;
}

static bool download_file(const std::string& url, const fs::path& dest) {
    if (fs::exists(dest) && fs::file_size(dest) > 0) return true;
    return http_download(url, dest);
}

struct DLTask { std::string url; fs::path dest; };

static void parallel_dl(std::vector<DLTask>& tasks, int nthreads = 16) {
    if (tasks.empty()) return;
    std::atomic<size_t> cursor{0}, ndone{0};
    size_t total = tasks.size();

    auto worker = [&]() {
        for (size_t i; (i = cursor.fetch_add(1, std::memory_order_relaxed)) < total; ) {
            download_file(tasks[i].url, tasks[i].dest);
            ndone.fetch_add(1, std::memory_order_relaxed);
        }
    };

    int n = std::min(nthreads, (int)total);
    std::vector<std::thread> pool(n);
    for (auto& t : pool) t = std::thread(worker);

    while (ndone.load(std::memory_order_relaxed) < total) {
        printf("  %zu/%zu\r", ndone.load(std::memory_order_relaxed), total);
        fflush(stdout);
        Sleep(100);
    }
    for (auto& t : pool) t.join();
    printf("  %zu/%zu\n", total, total);
}

struct Config {
    std::string username  = "Player";
    std::string java_path = "javaw";
    int         ram_gb    = 2;
};

static inline std::string esc_json(const std::string& s) {
    std::string r;
    r.reserve(s.size() + 4);
    for (char c : s) {
        if      (c == '"')  r += "\\\"";
        else if (c == '\\') r += "\\\\";
        else r += c;
    }
    return r;
}

static Config load_config(const fs::path& p) {
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

static void save_config(const Config& c, const fs::path& p) {
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "{\n  \"username\": \"%s\",\n  \"java_path\": \"%s\",\n  \"ram_gb\": %d\n}\n",
        esc_json(c.username).c_str(), esc_json(c.java_path).c_str(), c.ram_gb);
    if (n > 0) { std::ofstream f(p); f.write(buf, n); }
}

static inline bool check_java(const std::string& java) {
    return system(("\"" + java + "\" -version > NUL 2>&1").c_str()) == 0;
}

struct MCVer { int v[3] = {}; };

static MCVer parse_mc_ver(const std::string& s) {
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

static inline int cmp_ver(const MCVer& a, const MCVer& b) {
    for (int i = 0; i < 3; ++i) {
        if (a.v[i] < b.v[i]) return -1;
        if (a.v[i] > b.v[i]) return  1;
    }
    return 0;
}

static inline int required_jdk(const std::string& mc) {
    static const MCVer v117 = parse_mc_ver("1.17");
    static const MCVer v121 = parse_mc_ver("1.21");
    MCVer v = parse_mc_ver(mc);
    if (cmp_ver(v, v117) < 0) return 8;
    if (cmp_ver(v, v121) < 0) return 17;
    return 21;
}

static std::string get_runtime_component_for_version(const std::string& mc) {
    static const MCVer v117  = parse_mc_ver("1.17");
    static const MCVer v1205 = parse_mc_ver("1.20.5");
    MCVer v = parse_mc_ver(mc);
    if (cmp_ver(v, v117)  < 0) return "jre-legacy";
    if (cmp_ver(v, v1205) < 0) return "java-runtime-gamma";
    return "java-runtime-delta";
}

static std::string make_offline_uuid(const std::string& name) {
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

static inline bool lib_applies(const JVal& lib) {
    if (!lib.has("rules")) return true;
    bool allowed = false;
    for (size_t i = 0; i < lib["rules"].size(); ++i) {
        const auto& rule = lib["rules"].arr[i];
        bool match = !rule.has("os") || rule["os"]["name"].str() == "windows";
        if (match) allowed = (rule["action"].str() == "allow");
    }
    return allowed;
}

static std::string find_java_in_dir(const fs::path& dir) {
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

static std::string maven_path(const std::string& coords) {
    size_t c1 = coords.find(':');
    if (c1 == std::string::npos) return {};
    size_t c2 = coords.find(':', c1 + 1);
    if (c2 == std::string::npos) return {};

    std::string group    = coords.substr(0, c1);
    std::string artifact = coords.substr(c1 + 1, c2 - c1 - 1);
    std::string ver      = coords.substr(c2 + 1);

    size_t cls_pos = ver.find(':');
    std::string classifier;
    if (cls_pos != std::string::npos) {
        classifier = ver.substr(cls_pos + 1);
        ver = ver.substr(0, cls_pos);
    }

    std::replace(group.begin(), group.end(), '.', '/');

    std::string fname = artifact + "-" + ver;
    if (!classifier.empty()) fname += "-" + classifier;
    fname += ".jar";

    return group + "/" + artifact + "/" + ver + "/" + fname;
}

static const char* MANIFEST_URL   = "https://launchermeta.mojang.com/mc/game/version_manifest.json";
static const char* RESOURCES_URL  = "https://resources.download.minecraft.net/";
static const char* RUNTIME_ALL_URL =
    "https://launchermeta.mojang.com/v1/products/java-runtime/"
    "2ec0cc96c44e5a76b9c8b7c39df7210883d12871/all.json";
static const char* FABRIC_META_BASE = "https://meta.fabricmc.net/v2/versions/";

static bool install_bundled_jre(const fs::path& root, Config& cfg, const fs::path& cfg_path,
                                 const std::string& mc_ver = "") {
    std::string component = mc_ver.empty() ? "jre-legacy"
                                           : get_runtime_component_for_version(mc_ver);
    fs::path jre_dir = root / "runtime" / component;

    std::string existing = find_java_in_dir(jre_dir);
    if (!existing.empty()) {
        printf("  Found Mojang JRE (%s): %s\n", component.c_str(), existing.c_str());
        cfg.java_path = existing;
        save_config(cfg, cfg_path);
        return true;
    }

    printf("\nNo bundled JRE found for '%s'.\n", component.c_str());
    printf("Download Mojang JRE (%s) automatically? (y/n): ", component.c_str());
    std::string ans;
    std::getline(std::cin, ans);
    if (ans.empty() || (ans[0] != 'y' && ans[0] != 'Y')) return false;

    fputs("  Fetching Mojang runtime index...\n", stdout);
    std::string all_str = http_get_str(RUNTIME_ALL_URL);
    if (all_str.empty()) { fputs("  Failed to fetch runtime index.\n", stderr); return false; }
    auto all_j = parse_json(all_str);

    const char* platform = "windows-x64";
    if (!all_j.has(platform) || !all_j[platform].has(component)) {
        fprintf(stderr, "  Component '%s' not found for %s.\n", component.c_str(), platform);
        return false;
    }
    const auto& comp_arr = all_j[platform][component];
    if (!comp_arr.is_array() || !comp_arr.size()) {
        fputs("  Empty component entry.\n", stderr); return false;
    }
    std::string manifest_url = comp_arr[size_t(0)]["manifest"]["url"].str();
    if (manifest_url.empty()) { fputs("  No manifest URL.\n", stderr); return false; }

    printf("  Fetching file manifest for '%s'...\n", component.c_str());
    std::string mf_str = http_get_str(manifest_url);
    if (mf_str.empty()) { fputs("  Failed to fetch file manifest.\n", stderr); return false; }
    auto mf = parse_json(mf_str);

    fs::create_directories(jre_dir);
    const auto& files = mf["files"];

    std::vector<DLTask> tasks;
    tasks.reserve(files.size());
    for (const auto& kv : files.obj) {
        const std::string& rel_path = kv.first;
        const JVal& entry           = kv.second;
        if (entry["type"].str() == "directory") {
            fs::create_directories(jre_dir / rel_path);
            continue;
        }
        if (entry["type"].str() != "file") continue;
        if (!entry.has("downloads") || !entry["downloads"].has("raw")) continue;
        std::string dl_url = entry["downloads"]["raw"]["url"].str();
        if (dl_url.empty()) continue;
        tasks.push_back({std::move(dl_url), jre_dir / rel_path});
    }

    printf("  Downloading %zu JRE files...\n", tasks.size());
    parallel_dl(tasks, 16);

    std::string found = find_java_in_dir(jre_dir);
    if (found.empty()) {
        fprintf(stderr, "  javaw.exe not found after install in: %s\n", jre_dir.string().c_str());
        return false;
    }

    printf("  Mojang JRE (%s) installed: %s\n", component.c_str(), found.c_str());
    cfg.java_path = found;
    save_config(cfg, cfg_path);
    return true;
}

static void download_libraries_to_tasks(const fs::path& root, const JVal& vj,
                                         std::vector<DLTask>& tasks) {
    if (!vj.has("libraries")) return;
    fs::path lib_dir = root / "libraries";
    for (size_t i = 0; i < vj["libraries"].size(); ++i) {
        const auto& lib = vj["libraries"].arr[i];
        if (!lib_applies(lib)) continue;

        if (lib.has("name") && !lib.has("downloads")) {
            std::string path = maven_path(lib["name"].str());
            if (path.empty()) continue;
            std::string base_url = lib.has("url") ? lib["url"].str() : "https://libraries.minecraft.net/";
            if (!base_url.empty() && base_url.back() != '/') base_url += '/';
            tasks.push_back({base_url + path, lib_dir / path});
            continue;
        }

        if (!lib.has("downloads")) continue;

        std::string nat_cls;
        bool is_native = false;
        if (lib.has("natives") && lib["natives"].has("windows")) {
            nat_cls = lib["natives"]["windows"].str();
            const char* arch = sizeof(void*) == 8 ? "64" : "32";
            size_t pos = nat_cls.find("${arch}");
            if (pos != std::string::npos) nat_cls.replace(pos, 7, arch);
            is_native = true;
        }

        auto push_art = [&](const std::string& cls) {
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
            if (!u.empty() && !p.empty()) tasks.push_back({u, lib_dir / p});
        };

        if (is_native) push_art(nat_cls);
        push_art({});
    }
}

static void extract_natives(const fs::path& root, const std::string& version, const JVal& vj) {
    if (!vj.has("libraries")) return;
    fs::path lib_dir = root / "libraries";
    fs::path nat_dir = root / "versions" / version / "natives";
    fs::create_directories(nat_dir);
    for (size_t i = 0; i < vj["libraries"].size(); ++i) {
        const auto& lib = vj["libraries"].arr[i];
        if (!lib_applies(lib)) continue;
        if (!lib.has("natives") || !lib["natives"].has("windows")) continue;
        std::string nat_cls = lib["natives"]["windows"].str();
        const char* arch = sizeof(void*) == 8 ? "64" : "32";
        size_t pos = nat_cls.find("${arch}");
        if (pos != std::string::npos) nat_cls.replace(pos, 7, arch);
        if (!lib.has("downloads") || !lib["downloads"].has("classifiers")) continue;
        if (!lib["downloads"]["classifiers"].has(nat_cls)) continue;
        const auto& p = lib["downloads"]["classifiers"][nat_cls]["path"].str();
        if (p.empty()) continue;
        fs::path jar = lib_dir / p;
        if (!fs::exists(jar)) continue;
        system(("tar -xf \"" + jar.string() + "\" -C \"" + nat_dir.string() +
                "\" --exclude=META-INF 2>NUL").c_str());
    }
}

static bool download_assets(const fs::path& root, const JVal& vj) {
    const auto& idx_url = vj["assetIndex"]["url"].str();
    const auto& idx_id  = vj["assetIndex"]["id"].str();
    if (idx_url.empty() || idx_id.empty()) {
        fputs("  No asset index in version JSON.\n", stderr);
        return false;
    }

    fs::path idx_file = root / "assets" / "indexes" / (idx_id + ".json");
    fs::create_directories(idx_file.parent_path());

    std::string idx_str;
    if (fs::exists(idx_file)) {
        std::ifstream f(idx_file);
        idx_str.assign(std::istreambuf_iterator<char>(f), {});
    } else {
        idx_str = http_get_str(idx_url);
        if (idx_str.empty()) { fputs("  Failed to fetch asset index.\n", stderr); return false; }
        std::ofstream f(idx_file); f << idx_str;
    }

    auto idx_json = parse_json(idx_str);
    const auto& objs = idx_json["objects"];

    std::vector<DLTask> tasks;
    tasks.reserve(objs.size());
    for (const auto& kv : objs.obj) {
        const auto& hash = kv.second["hash"].str();
        if (hash.size() < 2) continue;
        std::string pfx = hash.substr(0, 2);
        fs::path dest   = root / "assets" / "objects" / pfx / hash;
        if (fs::exists(dest) && fs::file_size(dest) > 0) continue;
        tasks.push_back({std::string(RESOURCES_URL) + pfx + "/" + hash, std::move(dest)});
    }

    printf("  Fetching %zu assets (%zu already cached)...\n",
           objs.size(), objs.size() - tasks.size());
    parallel_dl(tasks, 24);
    return true;
}

static bool download_minecraft_base(const fs::path& root, const std::string& version,
                                     const JVal& manifest, bool print_steps = true) {
    std::string ver_url;
    for (size_t i = 0; i < manifest["versions"].size(); ++i) {
        const auto& v = manifest["versions"].arr[i];
        if (v["id"].str() == version) { ver_url = v["url"].str(); break; }
    }
    if (ver_url.empty()) {
        fprintf(stderr, "Version %s not found in manifest.\n", version.c_str());
        return false;
    }

    fs::path ver_dir  = root / "versions" / version;
    fs::path ver_json = ver_dir / (version + ".json");
    fs::path ver_jar  = ver_dir / (version + ".jar");
    fs::create_directories(ver_dir);

    if (print_steps) printf("[2/5] Fetching %s version JSON...\n", version.c_str());
    std::string ver_str;
    if (fs::exists(ver_json)) {
        std::ifstream f(ver_json); ver_str.assign(std::istreambuf_iterator<char>(f), {});
    } else {
        ver_str = http_get_str(ver_url);
        if (ver_str.empty()) { fputs("Failed to fetch version JSON.\n", stderr); return false; }
        std::ofstream f(ver_json); f << ver_str;
    }
    auto vj = parse_json(ver_str);

    if (print_steps) fputs("[3/5] Downloading client JAR...\n", stdout);
    if (!download_file(vj["downloads"]["client"]["url"].str(), ver_jar)) {
        fputs("Failed to download client JAR.\n", stderr); return false;
    }

    if (print_steps) fputs("[4/5] Downloading libraries...\n", stdout);
    std::vector<DLTask> lib_tasks;
    download_libraries_to_tasks(root, vj, lib_tasks);
    parallel_dl(lib_tasks, 16);
    extract_natives(root, version, vj);

    if (print_steps) fputs("[5/5] Downloading assets...\n", stdout);
    download_assets(root, vj);

    return true;
}

static bool download_fabric(const fs::path& root, const std::string& mc_version,
                              const JVal& manifest) {
    printf("Fetching Fabric loaders for Minecraft %s...\n", mc_version.c_str());
    std::string loaders_str = http_get_str(std::string(FABRIC_META_BASE) + "loader/" + mc_version);
    if (loaders_str.empty()) {
        fputs("Failed to fetch Fabric loader list. This MC version may not be supported by Fabric.\n", stderr);
        return false;
    }
    auto loaders_j = parse_json(loaders_str);
    if (!loaders_j.is_array() || !loaders_j.size()) {
        fputs("No Fabric loaders available for this Minecraft version.\n", stderr);
        return false;
    }

    const std::string& loader_ver = loaders_j[size_t(0)]["loader"]["version"].str();
    if (loader_ver.empty()) { fputs("Could not determine Fabric loader version.\n", stderr); return false; }
    printf("Using Fabric Loader: %s\n", loader_ver.c_str());

    std::string fabric_id = "fabric-loader-" + loader_ver + "-" + mc_version;
    fs::path ver_dir  = root / "versions" / fabric_id;
    fs::path ver_json = ver_dir / (fabric_id + ".json");
    fs::create_directories(ver_dir);

    fputs("[1/5] Fetching Fabric profile JSON...\n", stdout);
    std::string profile_url = std::string(FABRIC_META_BASE) + "loader/" + mc_version +
                              "/" + loader_ver + "/profile/json";
    std::string profile_str;
    if (fs::exists(ver_json)) {
        std::ifstream f(ver_json); profile_str.assign(std::istreambuf_iterator<char>(f), {});
    } else {
        profile_str = http_get_str(profile_url);
        if (profile_str.empty()) { fputs("Failed to fetch Fabric profile JSON.\n", stderr); return false; }
        std::ofstream f(ver_json); f << profile_str;
    }
    auto fabric_vj = parse_json(profile_str);

    printf("[2/5] Downloading base Minecraft %s...\n", mc_version.c_str());
    if (!download_minecraft_base(root, mc_version, manifest, false)) {
        fputs("Failed to download base Minecraft for Fabric.\n", stderr);
        return false;
    }

    fputs("[3/5] Downloading Fabric libraries...\n", stdout);
    std::vector<DLTask> fabric_lib_tasks;
    download_libraries_to_tasks(root, fabric_vj, fabric_lib_tasks);
    parallel_dl(fabric_lib_tasks, 16);

    fputs("[4/5] (assets already fetched with base MC)\n", stdout);

    printf("\nFabric install complete: %s\n", fabric_id.c_str());
    return true;
}

using VarMap = std::unordered_map<std::string, std::string>;

static std::string tok_replace(const std::string& s, const VarMap& m) {
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

static std::string win_quote(const std::string& s) {
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

static std::string build_classpath(const fs::path& root, const JVal& vj, const JVal& parent_vj,
                                    const std::string& version, const std::string& jar_ver) {
    std::string cp;
    cp.reserve(8192);
    fs::path lib_dir = root / "libraries";

    auto add_libs = [&](const JVal& j) {
        if (!j.has("libraries")) return;
        for (size_t i = 0; i < j["libraries"].size(); ++i) {
            const auto& lib = j["libraries"].arr[i];
            if (!lib_applies(lib)) continue;
            if (lib.has("natives") && lib["natives"].has("windows")) continue;

            std::string path;
            if (lib.has("downloads") && lib["downloads"].has("artifact")) {
                path = lib["downloads"]["artifact"]["path"].str();
            } else if (lib.has("name")) {
                path = maven_path(lib["name"].str());
            }
            if (path.empty()) continue;
            fs::path jar = lib_dir / path;
            if (fs::exists(jar)) { cp += jar.string(); cp += ';'; }
        }
    };

    if (!parent_vj.is_null()) {
        add_libs(parent_vj);
        add_libs(vj);
    } else {
        add_libs(vj);
    }

    cp += (root / "versions" / jar_ver / (jar_ver + ".jar")).string();
    return cp;
}

static bool launch_version(const fs::path& root, const Config& cfg, const std::string& version) {
    fs::path vj_path = root / "versions" / version / (version + ".json");
    if (!fs::exists(vj_path)) { fprintf(stderr, "Not installed: %s\n", version.c_str()); return false; }

    std::ifstream f(vj_path);
    auto vj = parse_json(std::string(std::istreambuf_iterator<char>(f), {}));

    JVal parent_vj;
    std::string base_ver = version;
    if (vj.has("inheritsFrom")) {
        base_ver = vj["inheritsFrom"].str();
        fs::path pj_path = root / "versions" / base_ver / (base_ver + ".json");
        if (!fs::exists(pj_path)) {
            fprintf(stderr, "Base version '%s' not installed. Please reinstall.\n", base_ver.c_str());
            return false;
        }
        std::ifstream pf(pj_path);
        parent_vj = parse_json(std::string(std::istreambuf_iterator<char>(pf), {}));
    }

    const bool has_parent = !parent_vj.is_null();
    const JVal& base_vj   = has_parent ? parent_vj : vj;

    std::string cp        = build_classpath(root, vj, parent_vj, version, base_ver);
    std::string uuid      = make_offline_uuid(cfg.username);
    std::string nat       = (root / "versions" / base_ver / "natives").string();
    std::string assets    = (root / "assets").string();
    std::string asset_idx = base_vj["assetIndex"]["id"].str();
    std::string game_dir  = root.string();
    std::string ver_type  = vj.has("type") ? vj["type"].str() :
                            (base_vj.has("type") ? base_vj["type"].str() : "release");
    std::string main_cls  = vj["mainClass"].str();
    if (main_cls.empty()) main_cls = base_vj["mainClass"].str();
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
        {"launcher_version",  "3.0"},
    };

    std::vector<std::string> args;
    args.reserve(48);
    args.push_back("-Xmx" + std::to_string(cfg.ram_gb) + "G");
    args.push_back("-Xms512m");

    if (required_jdk(base_ver) <= 8) {
        args.push_back("-XX:+UseConcMarkSweepGC");
        args.push_back("-XX:+CMSIncrementalMode");
        args.push_back("-XX:HeapDumpPath=MojangTricksIntelDriversForPerformance_javaw.exe_minecraft.exe.heapdump");
    } else {
        args.insert(args.end(), {
            "-XX:+UseG1GC", "-XX:+UnlockExperimentalVMOptions",
            "-XX:G1NewSizePercent=20", "-XX:G1ReservePercent=20",
            "-XX:MaxGCPauseMillis=50", "-XX:G1HeapRegionSize=32M"
        });
    }

    auto collect_args = [&](const JVal& src, const std::string& which,
                             std::vector<std::string>& out) {
        if (!src.has("arguments") || !src["arguments"].has(which)) return;
        const auto& arr = src["arguments"][which];
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

    if (base_vj.has("arguments")) {
        std::vector<std::string> jvm_a, game_a;
        collect_args(base_vj, "jvm",  jvm_a);
        if (has_parent) collect_args(vj, "jvm", jvm_a);
        collect_args(base_vj, "game", game_a);
        for (auto& a : jvm_a)  args.push_back(a);
        args.push_back(main_cls);
        for (auto& a : game_a) args.push_back(a);
    } else {
        args.push_back("-Djava.library.path=" + nat);
        args.push_back("-Dorg.lwjgl.librarypath=" + nat);
        args.push_back("-Dfile.encoding=UTF-8");
        args.push_back("-cp");
        args.push_back(cp);
        args.push_back(main_cls);
        const auto& mc_args = base_vj["minecraftArguments"].str();
        for (size_t s = 0, e; s < mc_args.size(); s = e+1) {
            e = mc_args.find(' ', s);
            if (e == std::string::npos) { args.push_back(tok_replace(mc_args.substr(s), vars)); break; }
            args.push_back(tok_replace(mc_args.substr(s, e-s), vars));
        }
    }

    std::string java_exec = cfg.java_path;
    {
        size_t pos = java_exec.find("java.exe");
        if (pos != std::string::npos)
            java_exec.replace(pos, 8, "javaw.exe");
        else if (java_exec.size() >= 4 &&
                 java_exec.compare(java_exec.size()-4, 4, "java") == 0 &&
                 (java_exec.size() == 4 || java_exec[java_exec.size()-5] == '\\' ||
                  java_exec[java_exec.size()-5] == '/'))
            java_exec += "w";
    }

    std::string cmd;
    cmd.reserve(2048);
    cmd = win_quote(java_exec);
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

static std::vector<std::string> get_installed_versions(const fs::path& root) {
    std::vector<std::string> v;
    fs::path ver_dir = root / "versions";
    if (!fs::exists(ver_dir)) return v;
    std::error_code ec;
    for (auto& e : fs::directory_iterator(ver_dir, ec)) {
        if (!e.is_directory(ec)) continue;
        std::string name = e.path().filename().string();
        fs::path json_p  = e.path() / (name + ".json");
        if (!fs::exists(json_p)) continue;

        fs::path jar = e.path() / (name + ".jar");
        if (fs::exists(jar) && fs::file_size(jar) > 1024) { v.push_back(name); continue; }

        std::ifstream jf(json_p);
        std::string js((std::istreambuf_iterator<char>(jf)), {});
        auto jv = parse_json(js);
        if (jv.has("inheritsFrom")) {
            std::string base = jv["inheritsFrom"].str();
            fs::path base_jar = ver_dir / base / (base + ".jar");
            if (fs::exists(base_jar) && fs::file_size(base_jar) > 1024)
                v.push_back(name);
        }
    }
    std::sort(v.begin(), v.end());
    return v;
}

static void print_header(const char* title) {
    printf("\n================================================\n  %s\n================================================\n", title);
}

static void section_download(const fs::path& root, Config& cfg, const fs::path& cfg_path) {
    print_header("DOWNLOAD");

    fputs("\nLoader type:\n  [1] Vanilla\n  [2] Fabric\nChoice: ", stdout);
    std::string loader_choice;
    std::getline(std::cin, loader_choice);
    bool use_fabric = (loader_choice == "2");

    struct VE { std::string id, type; };
    std::vector<VE> entries;
    JVal manifest;

    if (use_fabric) {
        fputs("Fetching Fabric supported versions...\n", stdout);
        std::string fv_str = http_get_str(std::string(FABRIC_META_BASE) + "game");
        if (fv_str.empty()) {
            fputs("Failed to fetch Fabric game versions.\nPress Enter to continue...", stdout);
            std::cin.get(); return;
        }
        auto fv = parse_json(fv_str);
        if (!fv.is_array()) {
            fputs("Unexpected Fabric version response.\nPress Enter to continue...", stdout);
            std::cin.get(); return;
        }
        entries.reserve(fv.size());
        for (size_t i = 0; i < fv.size(); ++i) {
            const auto& v = fv.arr[i];
            entries.push_back({v["version"].str(), v["stable"].bval ? "release" : "snapshot"});
        }

        fputs("Fetching Mojang manifest (needed for base download)...\n", stdout);
        std::string ms = http_get_str(MANIFEST_URL);
        if (!ms.empty()) manifest = parse_json(ms);
    } else {
        fputs("Fetching version manifest...\n", stdout);
        std::string ms = http_get_str(MANIFEST_URL);
        if (ms.empty()) {
            fputs("Failed to fetch manifest.\nPress Enter to continue...", stdout);
            std::cin.get(); return;
        }
        manifest = parse_json(ms);
        entries.reserve(manifest["versions"].size());
        for (size_t i = 0; i < manifest["versions"].size(); ++i) {
            const auto& v = manifest["versions"].arr[i];
            entries.push_back({v["id"].str(), v["type"].str()});
        }
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

            if (use_fabric) {
                printf("\nDownload Fabric for Minecraft %s? (y/n): ", chosen.c_str());
                std::string ans; std::getline(std::cin, ans);
                if (ans.empty() || (ans[0] != 'y' && ans[0] != 'Y')) return;
                if (!install_bundled_jre(root, cfg, cfg_path, chosen))
                    fputs("Continuing without bundled JRE.\n", stdout);
                if (manifest.is_null()) {
                    fputs("Mojang manifest unavailable; cannot download base MC.\n", stderr);
                } else if (!download_fabric(root, chosen, manifest)) {
                    fputs("\nFabric download failed.\n", stderr);
                } else {
                    printf("\nFabric for Minecraft %s is ready.\n", chosen.c_str());
                }
            } else {
                fs::path jar = root / "versions" / chosen / (chosen + ".jar");
                if (fs::exists(jar) && fs::file_size(jar) > 1024) {
                    printf("\nVersion %s is already installed.\n", chosen.c_str());
                } else {
                    printf("\nDownload Minecraft %s? (y/n): ", chosen.c_str());
                    std::string ans; std::getline(std::cin, ans);
                    if (ans.empty() || (ans[0] != 'y' && ans[0] != 'Y')) return;
                    if (!install_bundled_jre(root, cfg, cfg_path, chosen))
                        fputs("Continuing without bundled JRE.\n", stdout);
                    fputs("\n[1/5] Manifest already fetched.\n", stdout);
                    if (!download_minecraft_base(root, chosen, manifest))
                        fputs("\nDownload failed.\n", stderr);
                    else
                        printf("\nDownload complete! %s is ready.\n", chosen.c_str());
                }
            }
            fputs("Press Enter to continue...", stdout); std::cin.get();
            return;
        } catch (...) { fputs("Invalid input.\n", stdout); }
    }
}

static void section_settings(Config& cfg, const fs::path& cfg_path) {
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

static void section_launch(const fs::path& root, Config& cfg, const fs::path& cfg_path) {
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
        std::string base_ver = chosen;
        {
            fs::path vj_path = root / "versions" / chosen / (chosen + ".json");
            if (fs::exists(vj_path)) {
                std::ifstream vf(vj_path);
                auto vj = parse_json(std::string(std::istreambuf_iterator<char>(vf), {}));
                if (vj.has("inheritsFrom")) base_ver = vj["inheritsFrom"].str();
            }
        }
        if (!check_java(cfg.java_path)) {
            printf("\nJava not found at: %s\nLocating bundled JRE...\n", cfg.java_path.c_str());
            if (!install_bundled_jre(root, cfg, cfg_path, base_ver)) {
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
