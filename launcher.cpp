/*
 * Compile: g++ -std=c++17 -O2 -o launcher.exe launcher.cpp -lwinhttp -lole32 -lshell32
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include <objbase.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <algorithm>
#include <filesystem>
#include <stdexcept>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

struct JVal {
    enum { Null, Bool, Num, Str, Arr, Obj } type = Null;
    bool        bval = false;
    double      nval = 0;
    std::string sval;
    std::vector<JVal>                         arr;
    std::vector<std::pair<std::string, JVal>> obj;

    bool is_null()   const { return type == Null; }
    bool is_string() const { return type == Str;  }
    bool is_array()  const { return type == Arr;  }
    bool is_object() const { return type == Obj;  }
    bool is_bool()   const { return type == Bool; }

    const JVal& operator[](const std::string& k) const {
        for (auto& p : obj) if (p.first == k) return p.second;
        static JVal null; return null;
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
    std::string str()  const { return sval; }
    double      num()  const { return nval; }
    size_t      size() const { return type == Arr ? arr.size() : obj.size(); }
};

static void skip_ws(const char*& p) {
    while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) ++p;
}

static std::string parse_string(const char*& p) {
    ++p;
    std::string s;
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

static JVal parse_value(const char*& p);

static JVal parse_object(const char*& p) {
    JVal v; v.type = JVal::Obj;
    ++p;
    skip_ws(p);
    while (*p && *p != '}') {
        skip_ws(p);
        if (*p != '"') break;
        std::string key = parse_string(p);
        skip_ws(p);
        if (*p == ':') ++p;
        skip_ws(p);
        JVal val = parse_value(p);
        v.obj.push_back({key, std::move(val)});
        skip_ws(p);
        if (*p == ',') ++p;
        skip_ws(p);
    }
    if (*p == '}') ++p;
    return v;
}

static JVal parse_array(const char*& p) {
    JVal v; v.type = JVal::Arr;
    ++p;
    skip_ws(p);
    while (*p && *p != ']') {
        v.arr.push_back(parse_value(p));
        skip_ws(p);
        if (*p == ',') ++p;
        skip_ws(p);
    }
    if (*p == ']') ++p;
    return v;
}

static JVal parse_value(const char*& p) {
    skip_ws(p);
    if (!*p) return JVal{};
    if (*p == '{') return parse_object(p);
    if (*p == '[') return parse_array(p);
    if (*p == '"') {
        JVal v; v.type = JVal::Str; v.sval = parse_string(p); return v;
    }
    if (strncmp(p, "true",  4) == 0) { JVal v; v.type = JVal::Bool; v.bval = true;  p += 4; return v; }
    if (strncmp(p, "false", 5) == 0) { JVal v; v.type = JVal::Bool; v.bval = false; p += 5; return v; }
    if (strncmp(p, "null",  4) == 0) { p += 4; return JVal{}; }
    char* end;
    double d = strtod(p, &end);
    JVal v; v.type = JVal::Num; v.nval = d; p = end; return v;
}

static JVal parse_json(const std::string& src) {
    const char* p = src.c_str();
    return parse_value(p);
}

struct ParsedUrl {
    std::wstring scheme, host, path;
    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
    bool is_https = true;
};

static std::wstring s2w(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    if (!w.empty() && w.back() == 0) w.pop_back();
    return w;
}

static std::string w2s(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
    if (!s.empty() && s.back() == 0) s.pop_back();
    return s;
}

static ParsedUrl crack_url(const std::wstring& url) {
    ParsedUrl r;
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[512]{}, path[2048]{}, scheme[16]{};
    uc.lpszHostName = host; uc.dwHostNameLength = 512;
    uc.lpszUrlPath  = path; uc.dwUrlPathLength  = 2048;
    uc.lpszScheme   = scheme; uc.dwSchemeLength  = 16;
    WinHttpCrackUrl(url.c_str(), 0, 0, &uc);
    r.host     = host;
    r.path     = path;
    r.scheme   = scheme;
    r.port     = uc.nPort;
    r.is_https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    return r;
}

static std::string http_get(const std::string& url_s) {
    std::wstring url = s2w(url_s);
    auto pu = crack_url(url);

    HINTERNET hSess = WinHttpOpen(L"MCLauncher/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return {};

    HINTERNET hConn = WinHttpConnect(hSess, pu.host.c_str(), pu.port, 0);
    if (!hConn) { WinHttpCloseHandle(hSess); return {}; }

    DWORD flags = pu.is_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", pu.path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return {}; }

    DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));

    bool sent = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                WinHttpReceiveResponse(hReq, nullptr);

    std::string result;
    if (sent) {
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
            std::string buf(avail, 0);
            DWORD read = 0;
            WinHttpReadData(hReq, buf.data(), avail, &read);
            result.append(buf.data(), read);
        }
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return result;
}

static bool download_file(const std::string& url, const fs::path& dest) {
    if (fs::exists(dest) && fs::file_size(dest) > 0) return true;
    auto data = http_get(url);
    if (data.empty()) {
        std::cerr << "  [FAIL] " << dest.filename().string() << "\n";
        return false;
    }
    fs::create_directories(dest.parent_path());
    std::ofstream f(dest, std::ios::binary);
    f.write(data.data(), data.size());
    return f.good();
}

static const std::string MANIFEST_URL  = "https://launchermeta.mojang.com/mc/game/version_manifest.json";
static const std::string RESOURCES_URL = "https://resources.download.minecraft.net/";
static const std::string MAIN_CLASS    = "net.minecraft.client.main.Main";

struct Config {
    std::string username  = "Player";
    std::string java_path = "java";
    int         ram_gb    = 2;
};

static std::string escape_json(const std::string& s) {
    std::string r;
    for (char c : s) {
        if (c == '"')  { r += "\\\""; }
        else if (c == '\\') { r += "\\\\"; }
        else r += c;
    }
    return r;
}

static std::string config_to_json(const Config& c) {
    return "{\n"
           "  \"username\": \""  + escape_json(c.username)  + "\",\n"
           "  \"java_path\": \"" + escape_json(c.java_path) + "\",\n"
           "  \"ram_gb\": "      + std::to_string(c.ram_gb) + "\n"
           "}\n";
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
    std::ofstream f(p);
    f << config_to_json(c);
}

static bool check_java(const std::string& java) {
    std::string cmd = "\"" + java + "\" -version > NUL 2>&1";
    return system(cmd.c_str()) == 0;
}

static std::string make_offline_uuid(const std::string& name) {
    std::string seed = "OfflinePlayer:" + name;
    unsigned char h[16]{};
    for (size_t i = 0; i < seed.size(); i++) {
        h[i % 16]      ^= (unsigned char)(seed[i] * (i + 1));
        h[(i + 3) % 16] += (unsigned char)seed[i];
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

static bool lib_applies(const JVal& lib) {
    if (!lib.has("rules")) return true;
    bool allowed = false;
    for (size_t i = 0; i < lib["rules"].size(); i++) {
        auto& rule = lib["rules"].arr[i];
        std::string action = rule["action"].str();
        bool matches = true;
        if (rule.has("os")) {
            std::string os = rule["os"]["name"].str();
            matches = (os == "windows");
        }
        if (matches) allowed = (action == "allow");
    }
    return allowed;
}

static std::string find_java_in_dir(const fs::path& dir) {
    if (!fs::exists(dir)) return "";
    std::error_code ec;
    for (auto& entry : fs::recursive_directory_iterator(dir, ec)) {
        if (entry.is_regular_file(ec)) {
            std::string fname = entry.path().filename().string();
            std::transform(fname.begin(), fname.end(), fname.begin(), ::tolower);
            if (fname == "java.exe") {
                return entry.path().string();
            }
        }
    }
    return "";
}

static bool install_bundled_jre(const fs::path& root, Config& cfg, const fs::path& cfg_path) {
    fs::path jre_dir = root / "jre";
    std::string existing = find_java_in_dir(jre_dir);
    if (!existing.empty()) {
        cfg.java_path = existing;
        save_config(cfg, cfg_path);
        return true;
    }

    std::cout << "\nThis version requires Java 8.\n";
    std::cout << "No bundled JRE found in: " << jre_dir.string() << "\n";
    std::cout << "Install Azul Zulu JDK 8 automatically via winget? (y/n): ";
    std::string ans;
    std::getline(std::cin, ans);
    if (ans.empty() || (ans[0] != 'y' && ans[0] != 'Y')) {
        std::cout << "Skipped JRE installation. Make sure Java 8 is available.\n";
        return false;
    }

    fs::create_directories(jre_dir);
    std::string loc = jre_dir.string();
    std::string cmd = "winget install Azul.Zulu.8.JDK"
                      " --location \"" + loc + "\""
                      " --source winget"
                      " --accept-source-agreements"
                      " --accept-package-agreements";
    std::cout << "\nRunning: " << cmd << "\n\n";
    int ret = system(cmd.c_str());
    if (ret != 0) {
        std::cerr << "winget returned error code " << ret << ".\n";
        std::cerr << "Try running as Administrator or install Java 8 manually.\n";
        return false;
    }

    std::string found = find_java_in_dir(jre_dir);
    if (found.empty()) {
        std::cerr << "java.exe not found in jre folder after install.\n";
        return false;
    }

    std::cout << "JRE installed: " << found << "\n";
    cfg.java_path = found;
    save_config(cfg, cfg_path);
    return true;
}

static JVal fetch_manifest() {
    std::cout << "Fetching version manifest...\n";
    auto s = http_get(MANIFEST_URL);
    if (s.empty()) { std::cerr << "Failed to fetch manifest.\n"; return JVal{}; }
    return parse_json(s);
}

static bool download_minecraft(const fs::path& root, const std::string& version) {
    auto manifest = fetch_manifest();
    if (manifest.is_null()) return false;

    std::string ver_url;
    for (size_t i = 0; i < manifest["versions"].size(); i++) {
        auto& v = manifest["versions"].arr[i];
        if (v["id"].str() == version) { ver_url = v["url"].str(); break; }
    }
    if (ver_url.empty()) {
        std::cerr << "Version " << version << " not found in manifest.\n";
        return false;
    }

    fs::path ver_dir  = root / "versions" / version;
    fs::path ver_json = ver_dir / (version + ".json");
    fs::path ver_jar  = ver_dir / (version + ".jar");
    fs::create_directories(ver_dir);

    std::cout << "[2/5] Fetching " << version << " version JSON...\n";
    std::string ver_str;
    if (fs::exists(ver_json)) {
        std::ifstream f(ver_json);
        ver_str = {std::istreambuf_iterator<char>(f), {}};
    } else {
        ver_str = http_get(ver_url);
        if (ver_str.empty()) { std::cerr << "Failed to fetch version JSON.\n"; return false; }
        std::ofstream f(ver_json); f << ver_str;
    }
    auto vj = parse_json(ver_str);

    std::cout << "[3/5] Downloading client JAR...\n";
    std::string jar_url = vj["downloads"]["client"]["url"].str();
    if (!download_file(jar_url, ver_jar)) {
        std::cerr << "Failed to download client JAR.\n"; return false;
    }

    std::cout << "[4/5] Downloading libraries...\n";
    fs::path lib_dir = root / "libraries";
    for (size_t i = 0; i < vj["libraries"].size(); i++) {
        auto& lib = vj["libraries"].arr[i];
        if (!lib_applies(lib)) continue;

        bool is_native = false;
        std::string native_classifier;
        if (lib.has("natives") && lib["natives"].has("windows")) {
            native_classifier = lib["natives"]["windows"].str();
            std::string arch = (sizeof(void*) == 8) ? "64" : "32";
            size_t pos = native_classifier.find("${arch}");
            if (pos != std::string::npos)
                native_classifier.replace(pos, 7, arch);
            is_native = true;
        }

        auto try_download = [&](const std::string& classifier) {
            if (lib.has("downloads")) {
                const JVal* art = nullptr;
                if (!classifier.empty() && lib["downloads"].has("classifiers")) {
                    if (lib["downloads"]["classifiers"].has(classifier))
                        art = &lib["downloads"]["classifiers"][classifier];
                } else if (lib["downloads"].has("artifact")) {
                    art = &lib["downloads"]["artifact"];
                }
                if (art && !art->is_null()) {
                    std::string u = (*art)["url"].str();
                    std::string p = (*art)["path"].str();
                    if (!u.empty() && !p.empty()) {
                        fs::path dest = lib_dir / p;
                        if (!download_file(u, dest))
                            std::cerr << "  warn: failed " << p << "\n";
                        else
                            std::cout << "  + " << p << "\n";
                        if (is_native) {
                            fs::path nat_dir = root / "natives";
                            fs::create_directories(nat_dir);
                            std::string cmd = "tar -xf \"" + dest.string() +
                                "\" -C \"" + nat_dir.string() + "\" --exclude=META-INF 2>NUL";
                            system(cmd.c_str());
                        }
                    }
                }
            }
        };

        if (is_native) try_download(native_classifier);
        try_download("");
    }

    std::cout << "[5/5] Downloading assets...\n";
    std::string idx_url = vj["assetIndex"]["url"].str();
    std::string idx_id  = vj["assetIndex"]["id"].str();
    fs::path idx_file   = root / "assets" / "indexes" / (idx_id + ".json");
    fs::create_directories(idx_file.parent_path());

    std::string idx_str;
    if (fs::exists(idx_file)) {
        std::ifstream f(idx_file);
        idx_str = {std::istreambuf_iterator<char>(f), {}};
    } else {
        idx_str = http_get(idx_url);
        if (idx_str.empty()) { std::cerr << "Failed to fetch asset index.\n"; return false; }
        std::ofstream f(idx_file); f << idx_str;
    }

    auto idx_json = parse_json(idx_str);
    auto& objects = idx_json["objects"];
    size_t total = objects.size(), done = 0;
    for (auto& kv : objects.obj) {
        auto& obj    = kv.second;
        std::string hash   = obj["hash"].str();
        std::string prefix = hash.substr(0, 2);
        fs::path dest = root / "assets" / "objects" / prefix / hash;
        if (!fs::exists(dest) || fs::file_size(dest) == 0) {
            std::string url = RESOURCES_URL + prefix + "/" + hash;
            download_file(url, dest);
        }
        done++;
        if (done % 50 == 0 || done == total)
            std::cout << "  Assets: " << done << "/" << total << "\r" << std::flush;
    }
    std::cout << "\n";
    return true;
}

static std::string build_classpath(const fs::path& root, const JVal& vj, const std::string& version) {
    std::string cp;
    fs::path lib_dir = root / "libraries";
    for (size_t i = 0; i < vj["libraries"].size(); i++) {
        auto& lib = vj["libraries"].arr[i];
        if (!lib_applies(lib)) continue;
        if (lib["natives"].has("windows")) continue;
        if (!lib.has("downloads") || !lib["downloads"].has("artifact")) continue;
        std::string p = lib["downloads"]["artifact"]["path"].str();
        if (p.empty()) continue;
        fs::path jar = lib_dir / p;
        if (fs::exists(jar))
            cp += jar.string() + ';';
    }
    fs::path client = root / "versions" / version / (version + ".jar");
    cp += client.string();
    return cp;
}

static bool launch_version(const fs::path& root, const Config& cfg, const std::string& version) {
    fs::path ver_json_path = root / "versions" / version / (version + ".json");
    if (!fs::exists(ver_json_path)) {
        std::cerr << "Version " << version << " is not installed.\n";
        return false;
    }

    std::ifstream f(ver_json_path);
    std::string s((std::istreambuf_iterator<char>(f)), {});
    auto vj = parse_json(s);

    std::string cp        = build_classpath(root, vj, version);
    std::string uuid      = make_offline_uuid(cfg.username);
    std::string nat       = (root / "natives").string();
    std::string asset_idx = vj["assetIndex"]["id"].str();
    std::string assets_dir = (root / "assets").string();
    std::string game_dir   = root.string();
    std::string jvm_args   = "-Xmx" + std::to_string(cfg.ram_gb) + "G -XX:+UseConcMarkSweepGC -XX:+CMSIncrementalMode";

    std::ostringstream cmd;
    cmd << "\"" << cfg.java_path << "\" "
        << jvm_args << " "
        << "-Djava.library.path=\"" << nat << "\" "
        << "-cp \"" << cp << "\" "
        << MAIN_CLASS << " "
        << "--username "    << cfg.username   << " "
        << "--version "     << version        << " "
        << "--gameDir \""   << game_dir       << "\" "
        << "--assetsDir \"" << assets_dir     << "\" "
        << "--assetIndex "  << asset_idx      << " "
        << "--uuid "        << uuid           << " "
        << "--accessToken 0 "
        << "--userType legacy";

    std::string cmdstr = cmd.str();
    std::cout << "\nLaunching Minecraft " << version << " as " << cfg.username << "...\n";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::wstring wcmd = s2w(cmdstr);
    std::vector<wchar_t> buf(wcmd.begin(), wcmd.end());
    buf.push_back(0);
    std::wstring wdir = s2w(game_dir);

    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
                        CREATE_NEW_CONSOLE, nullptr, wdir.c_str(), &si, &pi)) {
        std::cerr << "Failed to launch: error " << GetLastError() << "\n";
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

static std::vector<std::string> get_installed_versions(const fs::path& root) {
    std::vector<std::string> versions;
    fs::path ver_dir = root / "versions";
    if (!fs::exists(ver_dir)) return versions;
    std::error_code ec;
    for (auto& entry : fs::directory_iterator(ver_dir, ec)) {
        if (entry.is_directory(ec)) {
            std::string name = entry.path().filename().string();
            fs::path jar = entry.path() / (name + ".jar");
            if (fs::exists(jar) && fs::file_size(jar) > 1024)
                versions.push_back(name);
        }
    }
    std::sort(versions.begin(), versions.end());
    return versions;
}

static void print_header(const std::string& title) {
    std::cout << "\n";
    std::cout << "================================================\n";
    std::cout << "  " << title << "\n";
    std::cout << "================================================\n";
}

static void section_download(const fs::path& root, Config& cfg, const fs::path& cfg_path) {
    print_header("DOWNLOAD");

    auto manifest = fetch_manifest();
    if (manifest.is_null()) {
        std::cout << "Press Enter to continue...";
        std::cin.get();
        return;
    }

    struct VerEntry { std::string id, type; };
    std::vector<VerEntry> entries;
    for (size_t i = 0; i < manifest["versions"].size(); i++) {
        auto& v = manifest["versions"].arr[i];
        entries.push_back({v["id"].str(), v["type"].str()});
    }

    std::cout << "\nFilter: (1) Releases only  (2) All versions\nChoice: ";
    std::string filter_in;
    std::getline(std::cin, filter_in);
    bool releases_only = (filter_in != "2");

    std::vector<VerEntry> filtered;
    for (auto& e : entries) {
        if (releases_only && e.type != "release") continue;
        filtered.push_back(e);
    }

    int page = 0;
    const int PAGE_SIZE = 20;
    while (true) {
        int total_pages = ((int)filtered.size() + PAGE_SIZE - 1) / PAGE_SIZE;
        int start = page * PAGE_SIZE;
        int end   = std::min(start + PAGE_SIZE, (int)filtered.size());

        std::cout << "\nVersions (page " << (page + 1) << "/" << total_pages << "):\n";
        for (int i = start; i < end; i++) {
            std::cout << "  [" << (i - start + 1) << "] " << filtered[i].id;
            if (filtered[i].type != "release") std::cout << " (" << filtered[i].type << ")";
            std::cout << "\n";
        }
        std::cout << "\nEnter number to select, 'n' next page, 'p' prev page, 'q' cancel: ";
        std::string input;
        std::getline(std::cin, input);

        if (input == "q" || input == "Q") return;
        if (input == "n" || input == "N") { if (page + 1 < total_pages) page++; continue; }
        if (input == "p" || input == "P") { if (page > 0) page--; continue; }

        try {
            int idx = std::stoi(input) - 1 + start;
            if (idx < 0 || idx >= (int)filtered.size()) { std::cout << "Invalid selection.\n"; continue; }
            std::string chosen = filtered[idx].id;

            fs::path jar = root / "versions" / chosen / (chosen + ".jar");
            bool installed = fs::exists(jar) && fs::file_size(jar) > 1024;
            if (installed) {
                std::cout << "\nVersion " << chosen << " is already installed.\n";
            } else {
                std::cout << "\nDownload Minecraft " << chosen << "? (y/n): ";
                std::string ans;
                std::getline(std::cin, ans);
                if (ans.empty() || (ans[0] != 'y' && ans[0] != 'Y')) return;

                if (!install_bundled_jre(root, cfg, cfg_path)) {
                    std::cout << "Continuing without bundled JRE. Ensure Java is available.\n";
                }

                std::cout << "\n[1/5] Manifest already fetched.\n";
                if (!download_minecraft(root, chosen)) {
                    std::cerr << "\nDownload failed.\n";
                } else {
                    std::cout << "\nDownload complete! Version " << chosen << " is ready.\n";
                }
            }
            std::cout << "Press Enter to continue...";
            std::cin.get();
            return;
        } catch (...) {
            std::cout << "Invalid input.\n";
        }
    }
}

static void section_settings(Config& cfg, const fs::path& cfg_path) {
    while (true) {
        print_header("SETTINGS");
        std::cout << "  [1] Username   : " << cfg.username  << "\n";
        std::cout << "  [2] RAM (GB)   : " << cfg.ram_gb   << "GB\n";
        std::cout << "  [3] Java Path  : " << cfg.java_path << "\n";
        std::cout << "  [4] Back\n";
        std::cout << "\nChoice: ";

        std::string input;
        std::getline(std::cin, input);

        if (input == "1") {
            std::cout << "New username [" << cfg.username << "]: ";
            std::string val;
            std::getline(std::cin, val);
            if (!val.empty()) cfg.username = val;
        } else if (input == "2") {
            std::cout << "RAM in GB [" << cfg.ram_gb << "]: ";
            std::string val;
            std::getline(std::cin, val);
            try {
                int gb = std::stoi(val);
                if (gb >= 1 && gb <= 64) cfg.ram_gb = gb;
                else std::cout << "Invalid value. Must be 1-64.\n";
            } catch (...) {}
        } else if (input == "3") {
            std::cout << "Java executable path [" << cfg.java_path << "]: ";
            std::string val;
            std::getline(std::cin, val);
            if (!val.empty()) {
                if (!check_java(val)) {
                    std::cout << "Warning: could not verify java at that path.\n";
                }
                cfg.java_path = val;
            }
        } else if (input == "4" || input == "q" || input == "Q") {
            break;
        }

        save_config(cfg, cfg_path);
        std::cout << "Settings saved.\n";
    }
}

static void section_launch(const fs::path& root, Config& cfg, const fs::path& cfg_path) {
    print_header("LAUNCH");

    auto versions = get_installed_versions(root);
    if (versions.empty()) {
        std::cout << "\nNo installed versions found. Go to Download first.\n";
        std::cout << "Press Enter to continue...";
        std::cin.get();
        return;
    }

    std::cout << "\nInstalled versions:\n";
    for (size_t i = 0; i < versions.size(); i++) {
        std::cout << "  [" << (i + 1) << "] " << versions[i] << "\n";
    }
    std::cout << "\nSelect version (or 'q' to cancel): ";
    std::string input;
    std::getline(std::cin, input);
    if (input == "q" || input == "Q") return;

    try {
        int idx = std::stoi(input) - 1;
        if (idx < 0 || idx >= (int)versions.size()) {
            std::cout << "Invalid selection.\n";
            std::cout << "Press Enter to continue...";
            std::cin.get();
            return;
        }
        std::string chosen = versions[idx];

        if (!check_java(cfg.java_path)) {
            std::cout << "\nJava not found at: " << cfg.java_path << "\n";
            std::cout << "Attempting to locate bundled JRE...\n";
            if (!install_bundled_jre(root, cfg, cfg_path)) {
                std::cerr << "Java unavailable. Set Java Path in Settings.\n";
                std::cout << "Press Enter to continue...";
                std::cin.get();
                return;
            }
        }

        if (!launch_version(root, cfg, chosen)) {
            std::cout << "Press Enter to continue...";
            std::cin.get();
        } else {
            std::cout << "Game launched! Exiting launcher...\n";
            Sleep(1500);
        }
    } catch (...) {
        std::cout << "Invalid input.\n";
        std::cout << "Press Enter to continue...";
        std::cin.get();
    }
}

int main() {
    SetConsoleOutputCP(CP_UTF8);

    wchar_t exe_path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
    fs::path root = fs::path(exe_path).parent_path();

    fs::path cfg_path = root / "config.json";
    Config cfg = load_config(cfg_path);

    if (cfg.username.empty() || cfg.username == "Player") {
        std::cout << "=== Minecraft Launcher ===\n\n";
        std::cout << "Enter your username: ";
        std::getline(std::cin, cfg.username);
        if (cfg.username.empty()) cfg.username = "Player";
        save_config(cfg, cfg_path);
    }

    while (true) {
        print_header("MINECRAFT LAUNCHER");
        std::cout << "  [1] Download\n";
        std::cout << "  [2] Settings\n";
        std::cout << "  [3] Launch\n";
        std::cout << "  [4] Exit\n";
        std::cout << "\nChoice: ";

        std::string input;
        std::getline(std::cin, input);

        if (input == "1") {
            section_download(root, cfg, cfg_path);
        } else if (input == "2") {
            section_settings(cfg, cfg_path);
        } else if (input == "3") {
            section_launch(root, cfg, cfg_path);
        } else if (input == "4" || input == "q" || input == "Q") {
            break;
        }
    }

    return 0;
}