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
#include <libpq-fe.h>
#include <openssl/evp.h>
#include "httplib.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

PGconn* db = nullptr;
std::mutex db_mtx;

// --- 1. СЛОВАРЬ (ru/en) ---
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

// --- 2. МИНИФИКАТОР ---
std::string minify_html(const std::string& html) {
    std::string out; out.reserve(html.size());
    bool in_space = false;
    for (size_t i = 0; i < html.size(); ++i) {
        char c = html[i];
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        if (c == ' ') {
            if (!in_space) { out.push_back(' '); in_space = true; }
        } else { in_space = false; out.push_back(c); }
    }
    return out;
}

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

// --- 3. КРИПТО ---
std::string hash_password(const std::string& password) {
    std::string salted = "ruttr_free_speech_salt_" + password;
    unsigned char hash[EVP_MAX_MD_SIZE]; unsigned int length = 0;
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
    std::random_device rd; std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    std::stringstream ss; ss << std::hex << dis(gen) << dis(gen);
    return ss.str();
}

// --- 4. ИНИЦИАЛИЗАЦИЯ И ПРОВЕРКА POSTGRESQL ---
bool pg_exec_simple(const char* sql) {
    PGresult* res = PQexec(db, sql);
    ExecStatusType st = PQresultStatus(res);
    if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
        std::cerr << "PG SQL error: " << PQerrorMessage(db) << "\n";
        PQclear(res);
        return false;
    }
    PQclear(res);
    return true;
}

PGresult* pg_query_params(const char* sql, const std::vector<std::string>& params) {
    std::vector<const char*> vals;
    vals.reserve(params.size());
    for (const auto& p : params) vals.push_back(p.c_str());

    PGresult* res = PQexecParams(
        db,
        sql,
        static_cast<int>(vals.size()),
        nullptr,
        vals.empty() ? nullptr : vals.data(),
        nullptr,
        nullptr,
        0
    );
    ExecStatusType st = PQresultStatus(res);
    if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
        std::cerr << "PG query error: " << PQerrorMessage(db) << "\n";
        PQclear(res);
        return nullptr;
    }
    return res;
}

bool check_db_health() {
    std::lock_guard<std::mutex> lock(db_mtx);
    if (!db) return false;

    if (PQstatus(db) != CONNECTION_OK) {
        PQreset(db);
        if (PQstatus(db) != CONNECTION_OK) {
            return false;
        }
    }

    PGresult* res = PQexec(db, "SELECT 1;");
    bool ok = (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0);
    if (res) PQclear(res);

    if (!ok) {
        PQreset(db);
        if (PQstatus(db) == CONNECTION_OK) {
            PGresult* retry = PQexec(db, "SELECT 1;");
            ok = (retry && PQresultStatus(retry) == PGRES_TUPLES_OK && PQntuples(retry) > 0);
            if (retry) PQclear(retry);
        }
    }
    return ok;
}

void init_db() {
    const char* db_url = std::getenv("DATABASE_URL");
    if (!db_url || !*db_url) {
        std::cerr << "DATABASE_URL is not set in environment\n";
        std::exit(1);
    }

    db = PQconnectdb(db_url);
    if (PQstatus(db) != CONNECTION_OK) {
        std::cerr << "Ошибка подключения к PostgreSQL: " << PQerrorMessage(db) << "\n";
        PQfinish(db);
        std::exit(1);
    }

    const char* create_sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at BIGINT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            likes INTEGER DEFAULT 0,
            created_at BIGINT NOT NULL
        );
    )";
    if (!pg_exec_simple(create_sql)) {
        PQfinish(db);
        std::exit(1);
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
    std::string user = "";
    PGresult* res = pg_query_params("SELECT username FROM sessions WHERE token = $1;", {token});
    if (res) {
        if (PQntuples(res) > 0) {
            user = PQgetvalue(res, 0, 0);
        }
        PQclear(res);
    }
    return user;
}

// --- 5. SSR СТРАНИЦЫ ---
std::string render_page(const std::string& current_user, const std::string& lang, const std::string& page = "home") {
    std::string posts_html;
    if (page == "home" || page == "explore") {
        std::lock_guard<std::mutex> lock(db_mtx);
        PGresult* res = pg_query_params(
            "SELECT id, username, content, likes, created_at FROM posts ORDER BY id DESC LIMIT 50;",
            {}
        );
        if (res) {
            int rows = PQntuples(res);
            for (int i = 0; i < rows; ++i) {
                std::string id_str = PQgetvalue(res, i, 0);
                std::string raw_author = PQgetvalue(res, i, 1);
                std::string raw_text = PQgetvalue(res, i, 2);
                std::string likes_str = PQgetvalue(res, i, 3);

                std::string author = escape_html(raw_author);
                std::string text = escape_html(raw_text);
                char initial = raw_author.empty()
                    ? '?'
                    : static_cast<char>(std::toupper(static_cast<unsigned char>(raw_author[0])));

                posts_html += "<article class='post-card'>"
                    "<div class='post-header'>"
                        "<div class='avatar'>" + std::string(1, initial) + "</div>"
                        "<div><span class='author-name'>" + author + "</span> <span class='handle'>@" + author + "</span></div>"
                    "</div>"
                    "<div class='post-body'>" + text + "</div>"
                    "<div class='post-actions'>"
                        "<button class='like-btn' onclick='likePost(\"" + id_str + "\", this)'>♥ <span>" + likes_str + "</span></button>"
                    "</div>"
                "</article>";
            }
            PQclear(res);
        }
    }
    if (posts_html.empty()) posts_html = "<div class='empty-state'>" + t(lang, "ruttr.empty") + "</div>";

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
        __LOGOUT_SECTION__
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

    auto replace_all = [](std::string& str, const std::string& from, const std::string& to) {
        size_t pos = 0;
        while ((pos = str.find(from, pos)) != std::string::npos) {
            str.replace(pos, from.length(), to);
            pos += to.length();
        }
    };

    replace_all(raw_html, "__LANG__", lang);
    replace_all(raw_html, "__LANG_NEXT__", t(lang, "ruttr.lang.next"));
    replace_all(raw_html, "__LANG_SWITCH__", t(lang, "ruttr.lang.switch"));
    replace_all(raw_html, "__POST_BUTTON__", t(lang, "ruttr.post.button"));
    replace_all(raw_html, "__LOGIN_BUTTON__", t(lang, "ruttr.auth.login"));
    replace_all(raw_html, "__REGISTER_BUTTON__", t(lang, "ruttr.auth.register"));
    replace_all(raw_html, "__USERNAME_PLACEHOLDER__", t(lang, "ruttr.auth.username"));
    replace_all(raw_html, "__PASSWORD_PLACEHOLDER__", t(lang, "ruttr.auth.password"));
    replace_all(raw_html, "__HOME_LINK__", t(lang, "ruttr.nav.home"));
    replace_all(raw_html, "__EXPLORE_LINK__", t(lang, "ruttr.nav.explore"));
    replace_all(raw_html, "__PROFILE_LINK__", t(lang, "ruttr.nav.profile"));
    replace_all(raw_html, "__LOGOUT_LINK__", t(lang, "ruttr.auth.logout"));
    replace_all(raw_html, "__TRENDS_TITLE__", t(lang, "ruttr.trends.title"));
    replace_all(raw_html, "__EMPTY_STATE__", t(lang, "ruttr.empty"));

    if (!current_user.empty()) {
        replace_all(raw_html, "__LOGOUT_SECTION__", R"(
        <form action="/api/logout" method="POST" style="display:inline;">
            <button type="submit" class="lang-btn">__LOGOUT_LINK__</button>
        </form>
        )");
    } else {
        replace_all(raw_html, "__LOGOUT_SECTION__", "");
    }

    return minify_html(raw_html);
}

int main() {
    init_db();
    const char* port_env = std::getenv("PORT");
    int port = port_env ? std::stoi(port_env) : 8080;
    httplib::Server svr;

    auto handle_health = [](const httplib::Request&, httplib::Response& res) {
        if (check_db_health()) {
            res.status = 200;
            res.set_content(R"({"status":"ok","db":"connected"})", "application/json");
        } else {
            res.status = 503;
            res.set_content(R"({"status":"error","db":"disconnected"})", "application/json");
        }
    };
    svr.Get("/health", handle_health);
    svr.Get("/api/health", handle_health);

    svr.Get("/lang", [](const httplib::Request& req, httplib::Response& res) {
        std::string l = req.get_param_value("set");
        if (l != "ru" && l != "en") l = "ru";
        res.set_header("Set-Cookie", "ruttr_lang=" + l + "; Path=/; Max-Age=31536000");
        res.set_redirect("/");
    });

    svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        std::string lang = get_cookie(req, "ruttr_lang");
        if (lang != "en" && lang != "ru") lang = "ru";
        std::string user = get_current_user(req);
        res.set_content(render_page(user, lang, "home"), "text/html; charset=utf-8");
    });

    svr.Get("/explore", [](const httplib::Request& req, httplib::Response& res) {
        std::string lang = get_cookie(req, "ruttr_lang");
        if (lang != "en" && lang != "ru") lang = "ru";
        std::string user = get_current_user(req);
        res.set_content(render_page(user, lang, "explore"), "text/html; charset=utf-8");
    });

    svr.Get("/profile", [](const httplib::Request& req, httplib::Response& res) {
        std::string lang = get_cookie(req, "ruttr_lang");
        if (lang != "en" && lang != "ru") lang = "ru";
        std::string user = get_current_user(req);
        res.set_content(render_page(user, lang, "profile"), "text/html; charset=utf-8");
    });

    // API
    svr.Post("/api/register", [](const httplib::Request& req, httplib::Response& res) {
        std::string user = req.get_param_value("username");
        std::string pass = req.get_param_value("password");
        if (user.size() < 3 || pass.size() < 4) { res.set_redirect("/"); return; }
        std::string hash = hash_password(pass);
        std::string now_str = std::to_string(static_cast<long long>(std::time(nullptr)));
        std::lock_guard<std::mutex> lock(db_mtx);
        PGresult* r = pg_query_params(
            "INSERT INTO users (username, password_hash, created_at) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING;",
            {user, hash, now_str}
        );
        if (r) PQclear(r);
        res.set_redirect("/");
    });

    svr.Post("/api/login", [](const httplib::Request& req, httplib::Response& res) {
        std::string user = req.get_param_value("username");
        std::string pass = req.get_param_value("password");
        std::string hash = hash_password(pass);
        std::lock_guard<std::mutex> lock(db_mtx);
        std::string uid_str;
        PGresult* r = pg_query_params(
            "SELECT id FROM users WHERE username = $1 AND password_hash = $2;",
            {user, hash}
        );
        if (r) {
            if (PQntuples(r) > 0) uid_str = PQgetvalue(r, 0, 0);
            PQclear(r);
        }
        if (!uid_str.empty()) {
            std::string token = gen_token();
            PGresult* ins = pg_query_params(
                "INSERT INTO sessions (token, user_id, username) VALUES ($1, $2, $3);",
                {token, uid_str, user}
            );
            if (ins) PQclear(ins);
            res.set_header("Set-Cookie", "ruttr_session=" + token + "; Path=/; HttpOnly; Max-Age=2592000");
        }
        res.set_redirect("/");
    });

    svr.Post("/api/logout", [](const httplib::Request& req, httplib::Response& res) {
        std::string token = get_cookie(req, "ruttr_session");
        if (!token.empty()) {
            std::lock_guard<std::mutex> lock(db_mtx);
            PGresult* r = pg_query_params("DELETE FROM sessions WHERE token = $1;", {token});
            if (r) PQclear(r);
        }
        res.set_header("Set-Cookie", "ruttr_session=; Path=/; Max-Age=0");
        res.set_redirect("/");
    });

    svr.Post("/api/post", [](const httplib::Request& req, httplib::Response& res) {
        std::string user = get_current_user(req);
        std::string content = req.get_param_value("content");
        if (!user.empty() && !content.empty() && content.size() <= 2000) {
            std::string now_str = std::to_string(static_cast<long long>(std::time(nullptr)));
            std::lock_guard<std::mutex> lock(db_mtx);
            std::string uid_str = "1";
            PGresult* ures = pg_query_params("SELECT id FROM users WHERE username = $1;", {user});
            if (ures) {
                if (PQntuples(ures) > 0) uid_str = PQgetvalue(ures, 0, 0);
                PQclear(ures);
            }
            PGresult* r = pg_query_params(
                "INSERT INTO posts (user_id, username, content, created_at) VALUES ($1, $2, $3, $4);",
                {uid_str, user, content, now_str}
            );
            if (r) PQclear(r);
        }
        res.set_redirect("/");
    });

    svr.Post("/api/like", [](const httplib::Request& req, httplib::Response& res) {
        std::string id_val = req.get_param_value("id");
        char* end = nullptr; long id = std::strtol(id_val.c_str(), &end, 10);
        if (*end != '\0' || id <= 0) {
            res.set_content("{\"error\":\"invalid id\"}", "application/json");
            return;
        }
        std::string likes = "0";
        std::lock_guard<std::mutex> lock(db_mtx);
        PGresult* r = pg_query_params(
            "UPDATE posts SET likes = likes + 1 WHERE id = $1 RETURNING likes;",
            {std::to_string(id)}
        );
        if (r) {
            if (PQntuples(r) > 0) likes = PQgetvalue(r, 0, 0);
            PQclear(r);
        }
        res.set_content("{\"likes\":\"" + likes + "\"}", "application/json");
    });

    std::cout << "RUTTR C++ Server (PostgreSQL) running on port " << port << "\n";
    svr.listen("0.0.0.0", port);
    PQfinish(db);
    return 0;
}