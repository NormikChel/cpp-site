#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <string>
#include <mutex>
#include <openssl/evp.h>
#include "httplib.h"
#include "json.hpp"

using json = nlohmann::json;
std::mutex db_mutex;

// Хэширование пароля через SHA-256 + соль
std::string hash_password(const std::string& password) {
    std::string salted = "regimewatch_salt_2026_" + password;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, salted.c_str(), salted.size());
    EVP_DigestFinal_ex(ctx, hash, &length);
    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

json load_users() {
    std::ifstream file("users.json");
    if (!file.is_open()) return json::array();
    json data;
    try {
        file >> data;
        if (!data.is_array()) return json::array();
    } catch (...) {
        return json::array();
    }
    return data;
}

void save_users(const json& users) {
    std::ofstream file("users.json");
    file << users.dump(4);
}

int main() {
    const char* port_env = std::getenv("PORT");
    int port = port_env ? std::stoi(port_env) : 8080;

    httplib::Server svr;

    // Главная страница (без всяких лишних ссылок)
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        std::string html = R"(
            <!DOCTYPE html>
            <html lang="ru">
            <head><meta charset="UTF-8"><title>RegimeWatch</title></head>
            <body style="font-family: sans-serif; max-width: 400px; margin: 50px auto;">
                <h2>Регистрация</h2>
                <form action="/register" method="POST">
                    <input type="text" name="username" placeholder="Логин" required><br><br>
                    <input type="password" name="password" placeholder="Пароль" required><br><br>
                    <button type="submit">Зарегистрироваться</button>
                </form>
                <hr>
                <h2>Вход</h2>
                <form action="/login" method="POST">
                    <input type="text" name="username" placeholder="Логин" required><br><br>
                    <input type="password" name="password" placeholder="Пароль" required><br><br>
                    <button type="submit">Войти</button>
                </form>
            </body>
            </html>
        )";
        res.set_content(html, "text/html");
    });

    // Регистрация с сохранением хэша
    svr.Post("/register", [](const httplib::Request& req, httplib::Response& res) {
        std::string user = req.get_param_value("username");
        std::string pass = req.get_param_value("password");

        if (user.empty() || pass.empty()) {
            res.set_content("<h1>Заполни все поля!</h1><a href='/'>Назад</a>", "text/html; charset=utf-8");
            return;
        }

        std::lock_guard<std::mutex> lock(db_mutex);
        json users = load_users();

        for (const auto& u : users) {
            if (u["username"] == user) {
                res.set_content("<h1>Ошибка: этот логин уже занят!</h1><a href='/'>Назад</a>", "text/html; charset=utf-8");
                return;
            }
        }

        users.push_back({{"username", user}, {"password_hash", hash_password(pass)}});
        save_users(users);

        res.set_content("<h1>Успешная регистрация!</h1><a href='/'>Назад</a>", "text/html; charset=utf-8");
    });

    // Вход со сверкой хэша
    svr.Post("/login", [](const httplib::Request& req, httplib::Response& res) {
        std::string user = req.get_param_value("username");
        std::string pass = req.get_param_value("password");
        std::string pass_hash = hash_password(pass);

        std::lock_guard<std::mutex> lock(db_mutex);
        json users = load_users();

        for (const auto& u : users) {
            if (u["username"] == user && u.value("password_hash", "") == pass_hash) {
                res.set_content("<h1>Здарова, " + user + "! Ты вошел в систему!</h1><a href='/'>На главную</a>", "text/html; charset=utf-8");
                return;
            }
        }

        res.set_content("<h1>Неверный логин или пароль!</h1><a href='/'>Назад</a>", "text/html; charset=utf-8");
    });

    std::cout << "Сервер запущен на порту " << port << "\n";
    svr.listen("0.0.0.0", port);
    return 0;
}
