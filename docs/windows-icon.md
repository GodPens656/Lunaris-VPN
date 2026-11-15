# Иконка Lunaris client 0.6.5

Исходник: `src/assets/icon_windows.svg`. В нём встроен вариант существующей
луны и звезды, подготовленный встроенным imagegen. Векторный контур
ограничивает силуэт скруглённым квадратом и удаляет артефакты за его краями.
Исходные `icon.png` и Android-иконка сохранены для прежнего инструментария.

Итоговый вариант подготовлен встроенным imagegen с таким промптом:

> Edit target: the provided existing Lunaris application icon. Change ONLY
> the outer square silhouette to a rounded square with corner radius about
> 22% of the tile width, and actual alpha transparency outside the rounded
> tile. Preserve the exact white crescent moon and star shape, their position,
> proportions, flat edges, and the existing pink-purple gradient background
> inside the tile. No new text, no added objects, no shadows, no extra
> decoration, no redesigned logo. A single centered square desktop application
> icon, tightly filling its square canvas with smooth rounded corners,
> transparent background outside.

`scripts/prepare_tauri.py` передаёт SVG штатной команде `tauri icon`.
Она экспортирует PNG и многоразмерный ICO с прозрачными углами;
результат используется для EXE, заголовка окна, трея и значка интерфейса.
Android launcher по-прежнему использует `src/assets/icon_android.png`.
