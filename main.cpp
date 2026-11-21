#include <iostream>
#include <cstdlib>
#include <string>
#include <curl/curl.h>
#include "httplib.h"
#include "json.hpp"

using json = nlohmann::json;

// Вспомогательная функция для получения ответа от API Back4app
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Функция отправки запросов в Back4app Database
std::pair<long, std::string> b4a_request(const std::string& endpoint, const std::string& method, 
                                         const std::string& body, const std::string& app_id, const std::string& rest_key) {
    CURL* curl = curl_easy_init();
    std::string response_string;
    long http_code = 0;

    if (curl) {
        std::string url = "https://back4app.com" + endpoint;
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, ("X-Parse-Application-Id: " + app_id).c_str());
        headers = curl_slist_append(headers, ("X-Parse-REST-API-Key: " + rest_key).c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

        if (method == "POST") {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        }

        curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    return {http_code, response_string};
}

int main() {
    const char* app_id_env = std::getenv("B4A_APP_ID");
    const char* rest_key_env = std::getenv("B4A_REST_KEY");
    if (!app_id_env || !rest_key_env) {
        std::cerr << "Ошибка: не заданы B4A_APP_ID или B4A_REST_KEY!\n";
        return 1;
    }
    std::string app_id(app_id_env);
    std::string rest_key(rest_key_env);

    const char* port_env = std::getenv("PORT");
    int port = port_env ? std::stoi(port_env) : 8080;

    curl_global_init(CURL_GLOBAL_ALL);
    httplib::Server svr;

    // Главная страница
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        std::string html = R"(
            <!DOCTYPE html>
            <html lang="ru">
            <head><meta charset="UTF-8"><title>C++ + Back4app</title></head>
            <body style="font-family: sans-serif; max-width: 400px; margin: 50px auto;">
                <h2>Регистрация (C++ & Back4app DB)</h2>
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

    // Регистрация через встроенный эндпоинт /users в Back4app
    svr.Post("/register", [&app_id, &rest_key](const httplib::Request& req, httplib::Response& res) {
        json payload = {
            {"username", req.get_param_value("username")},
            {"password", req.get_param_value("password")}
        };

        auto [code, reply] = b4a_request("/users", "POST", payload.dump(), app_id, rest_key);

        if (code == 201) {
            res.set_content("<h1>Успешная регистрация! Пользователь сохранен в Back4app!</h1><a href='/'>Назад</a>", "text/html; charset=utf-8");
        } else {
            res.set_content("<h1>Ошибка регистрации:</h1><pre>" + reply + "</pre><a href='/'>Назад</a>", "text/html; charset=utf-8");
        }
    });

    // Вход через встроенный эндпоинт /login в Back4app
    svr.Post("/login", [&app_id, &rest_key](const httplib::Request& req, httplib::Response& res) {
        std::string user = req.get_param_value("username");
        std::string pass = req.get_param_value("password");

        // Экранируем параметры для GET-запроса
        std::string query = "/login?username=" + httplib::detail::encode_url(user) + "&password=" + httplib::detail::encode_url(pass);
        auto [code, reply] = b4a_request(query, "GET", "", app_id, rest_key);

        if (code == 200) {
            res.set_content("<h1>Здарова, " + user + "! Ты вошел через C++ и Back4app!</h1>", "text/html; charset=utf-8");
        } else {
            res.set_content("<h1>Неверный логин или пароль!</h1><a href='/'>Назад</a>", "text/html; charset=utf-8");
        }
    });

    std::cout << "C++ сервер запущен на порту " << port << "\n";
    svr.listen("0.0.0.0", port);
    curl_global_cleanup();
    return 0;
}