#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <random>
#include <ctime>
#include <algorithm>
#include <sqlite3.h>
#include <openssl/evp.h>
#include "httplib.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

sqlite3* db = nullptr;
std::mutex db_mtx;

// --- 1. СЛОВАРЬ ЛОКАЛИЗАЦИИ (i18n в стиле GETTR) ---
std::map<std::string, std::map<std::string, std::string>> I18N = {
    {"ru", {
        {"ruttr.nav.home", "Главная"},
        {"ruttr.nav.explore", "Обзор"},
        {"ruttr.nav.profile", "Профиль"},
        {"ruttr.post.placeholder", "Что происходит? Свобода слова без цензуры..."},
        {"ruttr.post.button", "Опубликовать"},
        {"ruttr.auth.login", "Войти"},
        {"ruttr.auth.register", "Регистрация"},
        {"ruttr.auth.logout", "Выйти"},
        {"ruttr.auth.username", "Логин"},
        {"ruttr.auth.password", "Пароль"},
        {"ruttr.trends.title", "Актуальное в RUTTR"},
        {"ruttr.lang.switch", "English"},
        {"ruttr.lang.next", "en"},
        {"ruttr.empty", "Пока нет ни одного поста. Будь первым!"}
    }},
    {"en", {
        {"ruttr.nav.home", "Home"},
        {"ruttr.nav.explore", "Explore"},
        {"ruttr.nav.profile", "Profile"},
        {"ruttr.post.placeholder", "What's happening? Uncensored free speech..."},
        {"ruttr.post.button", "Post"},
        {"ruttr.auth.login", "Log In"},
        {"ruttr.auth.register", "Sign Up"},
        {"ruttr.auth.logout", "Log Out"},
        {"ruttr.auth.username", "Username"},
        {"ruttr.auth.password", "Password"},
        {"ruttr.trends.title", "Trending on RUTTR"},
        {"ruttr.lang.switch", "Русский"},
        {"ruttr.lang.next", "ru"},
        {"ruttr.empty", "No posts yet. Be the first to speak!"}
    }}
};

std::string t(const std::string& lang, const std::string& key) {
    auto l = I18N.count(lang) ? lang : "ru";
    if (I18N[l].count(key)) return I18N[l][key];
    return key;
}

// --- 2. МИНИФИКАТОР HTML/CSS/JS НА СЕРВЕРЕ ---
std::string minify_html(const std::string& html) {
    std::string out;
    out.reserve(html.size());
    bool in_space = false;
    for (size_t i = 0; i < html.size(); ++i) {
        char c = html[i];
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        if (c == ' ') {
            if (!in_space) {
                out.push_back(' ');
                in_space = true;
            }
        } else {
            in_space = false;
            out.push_back(c);
        }
    }
    return out;
}

// Экранирование HTML для защиты от XSS
std::string escape_html(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

// --- 3. КРИПТОГРАФИЯ (SHA-256 + ТОКЕНЫ СЕССИЙ) ---
std::string hash_password(const std::string& password) {
    std::string salted = "ruttr_free_speech_salt_" + password;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, salted.c_str(), static_cast<int>(salted.size()));
    EVP_DigestFinal_ex(ctx, hash, &length);
    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < length; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

std::string gen_token() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    std::stringstream ss;
    ss << std::hex << dis(gen) << dis(gen);
    return ss.str();
}

// --- 4. ИНИЦИАЛИЗАЦИЯ SQLITE3 (db.sqlite3) ---
void init_db() {
    if (sqlite3_open("db.sqlite3", &db) != SQLITE_OK) {
        std::cerr << "Ошибка открытия db.sqlite3\n";
        exit(1);
    }
    const char* sql = R"(
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            likes INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL
        );
    )";
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::cerr << "SQL Error: " << err << "\n";
        sqlite3_free(err);
    }
}

std::string get_cookie(const httplib::Request& req, const std::string& name) {
    if (!req.has_header("Cookie")) return "";
    std::string cookies = req.get_header_value("Cookie");
    std::string key = name + "=";
    size_t pos = cookies.find(key);
    if (pos == std::string::npos) return "";
    pos += key.size();
    size_t end = cookies.find(';', pos);
    return cookies.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
}

std::string get_current_user(const httplib::Request& req) {
    std::string token = get_cookie(req, "ruttr_session");
    if (token.empty()) return "";
    std::lock_guard<std::mutex> lock(db_mtx);
    sqlite3_stmt* stmt;
    std::string user = "";
    if (sqlite3_prepare_v2(db, "SELECT username FROM sessions WHERE token = ?;", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            user = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }
    return user;
}

// --- 5. SSR ГЕНЕРАЦИЯ СТРАНИЦЫ В СТИЛЕ GETTR ---
std::string render_ssr_page(const std::string& current_user, const std::string& lang) {
    // --- посты ---
    std::string posts_html;
    {
        std::lock_guard<std::mutex> lock(db_mtx);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT id, username, content, likes, created_at FROM posts ORDER BY id DESC LIMIT 50;", -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int id = sqlite3_column_int(stmt, 0);
                std::string author = escape_html(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
                std::string text = escape_html(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
                int likes = sqlite3_column_int(stmt, 3);

                posts_html += "<article class='post-card'>"
                    "<div class='post-header'>"
                        "<div class='avatar'>" + std::string(1, std::toupper(static_cast<unsigned char>(author[0]))) + "</div>"
                        "<div><span class='author-name'>" + author + "</span> <span class='handle'>@" + author + "</span></div>"
                    "</div>"
                    "<div class='post-body'>" + text + "</div>"
                    "<div class='post-actions'>"
                        "<button class='like-btn' onclick='likePost(\"" + std::to_string(id) + "\", this)'>♥ <span>" + std::to_string(likes) + "</span></button>"
                    "</div>"
                "</article>";
            }
            sqlite3_finalize(stmt);
        }
    }
    if (posts_html.empty()) {
        posts_html = "<div class='empty-state'>" + t(lang, "ruttr.empty") + "</div>";
    }

    // --- композитор / авторизация ---
    std::string composer_or_auth;
    if (!current_user.empty()) {
        composer_or_auth = R"(
            <form class="composer" action="/api/post" method="POST">
                <textarea name="content" maxlength="777" placeholder=")" + t(lang, "ruttr.post.placeholder") + R"(" required></textarea>
                <div class="composer-footer">
                    <span class="user-badge">@)" + escape_html(current_user) + R"(</span>
                    <button type="submit" class="btn-primary">__POST_BUTTON__</button>
                </div>
            </form>
        )";
    } else {
        composer_or_auth = R"(
            <div class="auth-box">
                <form action="/api/login" method="POST" class="auth-form">
                    <input type="text" name="username" placeholder="__USERNAME_PLACEHOLDER__" required>
                    <input type="password" name="password" placeholder="__PASSWORD_PLACEHOLDER__" required>
                    <button type="submit" class="btn-primary">__LOGIN_BUTTON__</button>
                </form>
                <form action="/api/register" method="POST" class="auth-form">
                    <input type="text" name="username" placeholder="__USERNAME_PLACEHOLDER__" required>
                    <input type="password" name="password" placeholder="__PASSWORD_PLACEHOLDER__" required>
                    <button type="submit" class="btn-outline">__REGISTER_BUTTON__</button>
                </form>
            </div>
        )";
    }

    // --- raw HTML с плейсхолдерами (избегаем ") внутри R"()" ---
    std::string raw_html = R"(<!DOCTYPE html>
<html lang="__LANG__">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RUTTR — Free Speech</title>
<style>
:root{--accent:#FC223B;--accent-hover:#E01B32;--bg:#FFFFFF;--bg-sec:#F3F3F4;--border:#E8E8E8;--text:#1A1A1A;--text-sub:#6E6E73}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text)}
.layout{max-width:1200px;margin:0 auto;display:grid;grid-template-columns:240px 600px 300px;gap:24px;padding:0 16px}
@media(max-width:1150px){.layout{grid-template-columns:200px 1fr}.sidebar-right{display:none}}
@media(max-width:768px){.layout{grid-template-columns:1fr}.sidebar-left{display:none}}
.sidebar-left{position:sticky;top:0;height:100vh;padding:20px 0;display:flex;flex-direction:column;justify-content:space-between}
.logo{font-size:28px;font-weight:900;color:var(--accent);letter-spacing:-1px;display:flex;align-items:center;gap:8px;text-decoration:none;margin-bottom:24px}
.nav-item{display:block;padding:12px 16px;font-size:18px;font-weight:700;color:var(--text);text-decoration:none;border-radius:999px;margin-bottom:6px}
.nav-item:hover{background:var(--bg-sec)}
.feed-col{border-left:1px solid var(--border);border-right:1px solid var(--border);min-height:100vh}
.feed-header{position:sticky;top:0;background:rgba(255,255,255,0.88);backdrop-filter:blur(12px);padding:16px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;z-index:10}
.feed-header h1{font-size:20px;font-weight:800}
.composer{padding:16px 20px;border-bottom:8px solid var(--bg-sec)}
.composer textarea{width:100%;border:none;outline:none;resize:none;font-size:17px;min-height:84px;font-family:inherit}
.composer-footer{display:flex;justify-content:space-between;align-items:center;padding-top:12px;border-top:1px solid var(--border)}
.btn-primary{background:var(--accent);color:#fff;border:none;border-radius:999px;padding:10px 22px;font-weight:700;font-size:15px;cursor:pointer}
.btn-primary:hover{background:var(--accent-hover)}
.btn-outline{background:transparent;color:var(--accent);border:1px solid var(--accent);border-radius:999px;padding:9px 20px;font-weight:700;font-size:15px;cursor:pointer}
.auth-box{padding:16px 20px;border-bottom:8px solid var(--bg-sec);display:flex;flex-direction:column;gap:12px}
.auth-form{display:flex;gap:8px;flex-wrap:wrap}
.auth-form input{flex:1;min-width:120px;padding:10px 14px;border:1px solid var(--border);border-radius:999px;font-size:14px;outline:none}
.post-card{padding:16px 20px;border-bottom:1px solid var(--border)}
.post-card:hover{background:#FAFAFA}
.post-header{display:flex;align-items:center;gap:12px;margin-bottom:8px}
.avatar{width:40px;height:40px;border-radius:50%;background:var(--accent);color:#fff;font-weight:800;display:flex;align-items:center;justify-content:center;font-size:18px}
.author-name{font-weight:700;font-size:15px}
.handle{color:var(--text-sub);font-size:14px}
.post-body{font-size:16px;line-height:1.45;white-space:pre-wrap;word-break:break-word;margin-bottom:12px}
.like-btn{background:none;border:none;color:var(--text-sub);font-size:14px;font-weight:600;cursor:pointer;padding:6px 12px;border-radius:999px}
.like-btn:hover{background:#FFF0F2;color:var(--accent)}
.sidebar-right{padding:16px 0}
.trend-box{background:var(--bg-sec);border-radius:16px;padding:16px}
.trend-box h3{font-size:18px;font-weight:800;margin-bottom:12px}
.trend-item{padding:10px 0;border-top:1px solid var(--border);font-weight:700;font-size:15px}
.empty-state{padding:40px 20px;text-align:center;color:var(--text-sub)}
.lang-btn{background:var(--bg-sec);border:none;padding:8px 16px;border-radius:999px;font-weight:700;cursor:pointer;font-size:13px;text-decoration:none;color:var(--text)}
</style>
</head>
<body>
<div class="layout">
    <aside class="sidebar-left">
        <a class="nav-item" href="/">__HOME_LINK__</a>
        <a class="nav-item" href="/explore">__EXPLORE_LINK__</a>
        <a class="nav-item" href="/profile">__PROFILE_LINK__</a>
        )" + (!current_user.empty() ? R"(
        <form action="/api/logout" method="POST" style="display:inline;">
            <button type="submit" class="lang-btn">__LOGOUT_LINK__</button>
        </form>
        )" : "") + R"(
    </aside>
    <main class="feed-col">
        <div class="feed-header">
            <h1>🔥 RUTTR</h1>
            <a href="/lang?set=__LANG_NEXT__" class="lang-btn">__LANG_SWITCH__</a>
        </div>
        )" + composer_or_auth + R"(
        )" + posts_html + R"(
    </main>
    <aside class="sidebar-right">
        <div class="trend-box">
            <h3>__TRENDS_TITLE__</h3>
            <div class="trend-item">#FreeSpeech</div>
            <div class="trend-item">#RUTTR</div>
            <div class="trend-item">#Liberty</div>
        </div>
    </aside>
</div>
<script>
async function likePost(id, btn){
    const r = await fetch('/api/like?id=' + id, {method:'POST'});
    if(r.ok){
        const d = await r.json();
        btn.querySelector('span').textContent = d.likes;
        btn.style.color = '#FC223B';
    }
}
</script>
</body>
</html>
)";

    // --- замены плейсхолдеров (избегаем ") внутри raw) ---
    std::replace(raw_html.begin(), raw_html.end(), "__LANG__", lang);
    std::replace(raw_html.begin(), raw_html.end(), "__LANG_NEXT__", t(lang, "ruttr.lang.next"));
    std::replace(raw_html.begin(), raw_html.end(), "__LANG_SWITCH__", t(lang, "ruttr.lang.switch"));
    std::replace(raw_html.begin(), raw_html.end(), "__POST_BUTTON__", t(lang, "ruttr.post.button"));
    std::replace(raw_html.begin(), raw_html.end(), "__LOGIN_BUTTON__", t(lang, "ruttr.auth.login"));
    std::replace(raw_html.begin(), raw_html.end(), "__REGISTER_BUTTON__", t(lang, "ruttr.auth.register"));
    std::replace(raw_html.begin(), raw_html.end(), "__USERNAME_PLACEHOLDER__", t(lang, "ruttr.auth.username"));
    std::replace(raw_html.begin(), raw_html.end(), "__PASSWORD_PLACEHOLDER__", t(lang, "ruttr.auth.password"));
    std::replace(raw_html.begin(), raw_html.end(), "__HOME_LINK__", t(lang, "ruttr.nav.home"));
    std::replace(raw_html.begin(), raw_html.end(), "__EXPLORE_LINK__", t(lang, "ruttr.nav.explore"));
    std::replace(raw_html.begin(), raw_html.end(), "__PROFILE_LINK__", t(lang, "ruttr.nav.profile"));
    std::replace(raw_html.begin(), raw_html.end(), "__LOGOUT_LINK__", t(lang, "ruttr.auth.logout"));
    std::replace(raw_html.begin(), raw_html.end(), "__TRENDS_TITLE__", t(lang, "ruttr.trends.title"));
    std::replace(raw_html.begin(), raw_html.end(), "__EMPTY_STATE__", t(lang, "ruttr.empty"));

    return minify_html(raw_html);
}

int main() {
    init_db();
    const char* port_env = std::getenv("PORT");
    int port = port_env ? std::stoi(port_env) : 8080;
    httplib::Server svr;

    // Переключение языка (i18n)
    svr.Get("/lang", [](const httplib::Request& req, httplib::Response& res) {
        std::string l = req.get_param_value("set");
        if (l != "ru" && l != "en") l = "ru";
        res.set_header("Set-Cookie", "ruttr_lang=" + l + "; Path=/; Max-Age=31536000");
        res.set_redirect("/");
    });

    // Главная страница (SSR)
    svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        std::string lang = get_cookie(req, "ruttr_lang");
        if (lang != "en" && lang != "ru") lang = "ru";
        std::string user = get_current_user(req);
        res.set_content(render_ssr_page(user, lang), "text/html; charset=utf-8");
    });

    // Регистрация
    svr.Post("/api/register", [](const httplib::Request& req, httplib::Response& res) {
        std::string user = req.get_param_value("username");
        std::string pass = req.get_param_value("password");
        if (user.size() < 3 || pass.size() < 4) {
            res.set_redirect("/");
            return;
        }
        std::string hash = hash_password(pass);
        std::lock_guard<std::mutex> lock(db_mtx);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?);", -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, user.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int64(stmt, 3, std::time(nullptr));
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        res.set_redirect("/");
    });

    // Вход
    svr.Post("/api/login", [](const httplib::Request& req, httplib::Response& res) {
        std::string user = req.get_param_value("username");
        std::string pass = req.get_param_value("password");
        std::string hash = hash_password(pass);
        std::lock_guard<std::mutex> lock(db_mtx);
        sqlite3_stmt* stmt;
        int uid = -1;
        if (sqlite3_prepare_v2(db, "SELECT id FROM users WHERE username = ? AND password_hash = ?;", -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, user.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) uid = sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);
        }
        if (uid > 0) {
            std::string token = gen_token();
            if (sqlite3_prepare_v2(db, "INSERT INTO sessions (token, user_id, username) VALUES (?, ?, ?);", -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_int(stmt, 2, uid);
                sqlite3_bind_text(stmt, 3, user.c_str(), -1, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            res.set_header("Set-Cookie", "ruttr_session=" + token + "; Path=/; HttpOnly; Max-Age=2592000");
        }
        res.set_redirect("/");
    });

    // Выход
    svr.Post("/api/logout", [](const httplib::Request& req, httplib::Response& res) {
        std::string token = get_cookie(req, "ruttr_session");
        if (!token.empty()) {
            std::lock_guard<std::mutex> lock(db_mtx);
            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(db, "DELETE FROM sessions WHERE token = ?;", -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
        res.set_header("Set-Cookie", "ruttr_session=; Path=/; Max-Age=0");
        res.set_redirect("/");
    });

    // Создание поста
    svr.Post("/api/post", [](const httplib::Request& req, httplib::Response& res) {
        std::string user = get_current_user(req);
        std::string content = req.get_param_value("content");
        if (!user.empty() && !content.empty() && content.size() <= 2000) {
            std::lock_guard<std::mutex> lock(db_mtx);
            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(db, "INSERT INTO posts (user_id, username, content, created_at) VALUES (1, ?, ?, ?);", -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, user.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, content.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_int64(stmt, 3, std::time(nullptr));
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
        res.set_redirect("/");
    });

    // Лайк поста
    svr.Post("/api/like", [](const httplib::Request& req, httplib::Response& res) {
        const char* id_str = req.get_param_value("id").c_str();
        char* end = nullptr;
        long id = std::strtol(id_str, &end, 10);
        if (*end != '\0' || id <= 0) {
            res.set_content("{\"error\":\"invalid id\"}", "application/json");
            return;
        }
        int likes = 0;
        std::lock_guard<std::mutex> lock(db_mtx);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "UPDATE posts SET likes = likes + 1 WHERE id = ? RETURNING likes;", -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, static_cast<int>(id));
            if (sqlite3_step(stmt) == SQLITE_ROW) likes = sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);
        }
        res.set_content("{\"likes\":\"" + std::to_string(likes) + "\"}", "application/json");
    });

    std::cout << "RUTTR C++ Server running on port " << port << "\n";
    svr.listen("0.0.0.0", port);
    sqlite3_close(db);
    return 0;
}