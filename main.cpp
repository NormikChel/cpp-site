#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>
#include <mutex>
#include "httplib.h"
#include "json.hpp"

using json = nlohmann::json;
std::mutex db_mutex; // Защита от одновременной записи двумя юзерами

// Загрузка массива юзеров из файла
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

// Сохранение массива юзеров в файл
void save_users(const json& users) {
    std::ofstream file("users.json");
    file << users.dump(4);
}

int main() {
    const char* port_env = std::getenv("PORT");
    int port = port_env ? std::stoi(port_env) : 8080;

    httplib::Server svr;

    // Главная страница
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        std::string html = R"(
            <!DOCTYPE html>
            <html lang="ru">
            <head><meta charset="UTF-8"><title>C++ Fast JSON Site</title></head>
            <body style="font-family: sans-serif; max-width: 400px; margin: 50px auto;">
                <h2>Регистрация (Pure C++ & JSON)</h2>
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
                <hr>
                <a href="/users">Посмотреть список юзеров (JSON)</a>
            </body>
            </html>
        )";
        res.set_content(html, "text/html");
    });

    // Регистрация в JSON-массив
    svr.Post("/register", [](const httplib::Request& req, httplib::Response& res) {
        std::string user = req.get_param_value("username");
        std::string pass = req.get_param_value("password");

        std::lock_guard<std::mutex> lock(db_mutex);
        json users = load_users();

        // Проверяем, не занят ли логин
        for (const auto& u : users) {
            if (u["username"] == user) {
                res.set_content("<h1>Ошибка: этот логин уже занят!</h1><a href='/'>Назад</a>", "text/html; charset=utf-8");
                return;
            }
        }

        // Добавляем нового юзера в массив
        users.push_back({{"username", user}, {"password", pass}});
        save_users(users);

        res.set_content("<h1>Успешная регистрация в JSON!</h1><a href='/'>Назад</a>", "text/html; charset=utf-8");
    });

    // Вход
    svr.Post("/login", [](const httplib::Request& req, httplib::Response& res) {
        std::string user = req.get_param_value("username");
        std::string pass = req.get_param_value("password");

        std::lock_guard<std::mutex> lock(db_mutex);
        json users = load_users();

        for (const auto& u : users) {
            if (u["username"] == user && u["password"] == pass) {
                res.set_content("<h1>Здарова, " + user + "! Мгновенный вход на чистом C++!</h1><a href='/'>На главную</a>", "text/html; charset=utf-8");
                return;
            }
        }

        res.set_content("<h1>Неверный логин или пароль!</h1><a href='/'>Назад</a>", "text/html; charset=utf-8");
    });

    // Эндпоинт для проверки всех зарегистрированных (для отладки)
    svr.Get("/users", [](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(db_mutex);
        res.set_content(load_users().dump(4), "application/json");
    });

    std::cout << "C++ сервер запущен на порту " << port << "\n";
    svr.listen("0.0.0.0", port);
    return 0;
}
