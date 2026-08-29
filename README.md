# Levik VPN для Windows

<p align="center">
  <img src="build/icon.png" alt="Логотип Levik VPN" width="160" height="160" />
</p>

<p align="center">
  Простое приложение Levik VPN для компьютеров с Windows.<br />
  Исходный код открыт для изучения и независимой проверки.
</p>

<p align="center">
  <a href="https://github.com/Nort321/levik-vpn-windows/releases/latest/download/LevikVPN-Windows-x64.exe">Скачать для Windows</a> ·
  <a href="https://github.com/Nort321/levik-vpn-windows/releases/latest">Последний релиз</a> ·
  <a href="https://leviknet.com">Официальный сайт</a> ·
  <a href="https://t.me/leviksupportbot">Поддержка</a>
</p>

<p align="center">
  <a href="https://github.com/Nort321/levik-vpn-windows/actions/workflows/windows-release.yml">
    <img src="https://github.com/Nort321/levik-vpn-windows/actions/workflows/windows-release.yml/badge.svg" alt="Windows build" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="Лицензия AGPL-3.0" />
  </a>
</p>

## Возможности приложения

- Подключение и отключение VPN одной кнопкой.
- Полный системный TUN-туннель для TCP-, UDP- и игрового трафика.
- Автоматический выбор быстрого сервера.
- Список серверов с поиском и избранным.
- Поддержка обычных и мобильных LTE-серверов.
- Раздельное туннелирование для выбранных программ.
- Защита DNS во время подключения.
- Статистика скорости, трафика и времени подключения.
- Автоматическое восстановление соединения после сна или разблокировки компьютера.
- Цветовой индикатор подключения в системном трее и автоматическая проверка обновлений.
- Светлая и тёмная темы.

## Установка

1. Скачайте [последний установщик](https://github.com/Nort321/levik-vpn-windows/releases/latest/download/LevikVPN-Windows-x64.exe).
2. Откройте файл `LevikVPN-Windows-x64.exe`.
3. Выберите папку установки и завершите установку.
4. Войдите в Levik Account и выберите подписку.

Поддерживается **64-битная Windows 10 и Windows 11**. Приложение запрашивает права администратора: они нужны Windows для создания защищённого VPN-подключения.

Если установщик пока не подписан сертификатом разработчика, Windows может показать дополнительное предупреждение перед запуском. Загружайте приложение только с [официальной страницы Levik VPN](https://leviknet.com/downloads) или из этого репозитория.

## Открытый исходный код

В репозитории находится только Windows-клиент. Здесь нет сайта, серверной части, базы данных, производственных настроек, ключей подписи и пользовательских данных.

Основные каталоги:

```text
src/main/       системная логика, API и управление VPN
src/preload/    безопасный мост между интерфейсом и приложением
src/renderer/   пользовательский интерфейс
tests/          автоматические тесты
```

Приложение написано на TypeScript и Electron. Для VPN-подключения используется официальный [Xray-core](https://github.com/XTLS/Xray-core). Его бинарный файл не хранится в Git: GitHub Actions скачивает зафиксированную версию из официального релиза и проверяет контрольную сумму перед сборкой.

## Автоматические релизы

Каждый push в ветку `main` запускает проверки и сборку на Windows. После успешной сборки GitHub Actions создаёт новый Release с установщиком, файлами автоматического обновления и SHA-256 контрольными суммами.

Если в настройках репозитория добавлены секреты `WINDOWS_CSC_LINK` и `WINDOWS_CSC_KEY_PASSWORD`, установщик подписывается Authenticode-сертификатом. Без этих секретов CI создаёт рабочий, но неподписанный установщик.

## Сборка из исходного кода

Понадобятся Node.js 24, npm и Windows x64:

```powershell
npm ci
npm run download:xray
npm run lint
npm run build
npm test
npm run package:win
```

Готовый установщик появится в папке `release`.

## Конфиденциальность и безопасность

Токен аккаунта, ключ устройства и полученная конфигурация VPN хранятся локально в зашифрованном хранилище Windows. Правила обработки данных сервисом описаны в [политике конфиденциальности](https://leviknet.com/legal/privacy).

Если вы нашли уязвимость, не публикуйте чувствительные детали в Issues. Инструкция для безопасной связи находится в [SECURITY.md](SECURITY.md).

## Лицензия

Оригинальный исходный код Levik VPN распространяется по лицензии [GNU AGPLv3](LICENSE). Сторонние компоненты сохраняют собственные лицензии; подробности приведены в [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
