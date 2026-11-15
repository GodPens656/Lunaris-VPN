from __future__ import annotations

import asyncio
import copy
from datetime import datetime
from urllib.parse import urlsplit

import flet as ft

from .models import Status, UserError
from .deep_links import subscription_url
from .flags import flag_text
from . import APP_VERSION, CORE_VERSION
from .mihomo import MIHOMO_VERSION
from .latency import measure_latency, measure_profiles, transport_label
from .theme import BG, SURFACE, EDGE, TEXT, MUTED, MINT, YELLOW, configure_theme

LATENCY_LABELS = {"proxy": "via PROXY GET", "tcp": "TCP/UDP", "icmp": "ICMP"}
STATUS = {
    Status.DISCONNECTED: ("Отключено", MUTED), Status.CONNECTING: ("Подключается", YELLOW),
    Status.CONNECTED: ("Подключено", MINT), Status.DISCONNECTING: ("Отключается", YELLOW),
    Status.ERROR: ("Ошибка подключения", ft.Colors.ERROR),
}
NAV = [("Подключение", ft.Icons.SHIELD_OUTLINED), ("Серверы", ft.Icons.DNS_OUTLINED),
       ("Подписки", ft.Icons.LINK_ROUNDED), ("Настройки", ft.Icons.TUNE_ROUNDED), ("Журнал", ft.Icons.SUBJECT_ROUNDED)]


def text(value, size=14, color=TEXT, weight=None):
    return ft.Text(value, size=size, color=color, weight=weight)


def panel(content, *, padding=24, **kwargs):
    return ft.Container(content, bgcolor=SURFACE, border=ft.Border.all(1, EDGE), border_radius=20, padding=padding, **kwargs)


def dialog_field(**kwargs):
    # Flet 0.82 uses border properties; 1.0 exposes stateful border objects.
    if hasattr(ft, "OutlineInputBorder"):
        border_style = {"border": {
            ft.ControlState.DEFAULT: ft.OutlineInputBorder(border_radius=12, side=ft.BorderSide(1, EDGE)),
            ft.ControlState.FOCUSED: ft.OutlineInputBorder(border_radius=12, side=ft.BorderSide(2, MINT)),
        }}
    else:
        border_style = dict(border=ft.InputBorder.OUTLINE, border_radius=12,
            border_width=1, border_color=EDGE, focused_border_width=2, focused_border_color=MINT)
    return ft.TextField(
        color=TEXT, cursor_color=MINT, text_size=14,
        label_style=ft.TextStyle(color=MUTED, size=14),
        hint_style=ft.TextStyle(color=MUTED, size=13),
        filled=True, fill_color=ft.Colors.SURFACE_CONTAINER_LOWEST,
        content_padding=ft.Padding.symmetric(horizontal=16, vertical=18), **border_style, **kwargs)


def dialog_button(label, *, primary=False, on_click=None):
    style = ft.ButtonStyle(
        shape=ft.RoundedRectangleBorder(radius=12),
        padding=ft.Padding.symmetric(horizontal=18, vertical=14),
        text_style=ft.TextStyle(size=14, weight=ft.FontWeight.W_600),
        color={ft.ControlState.DEFAULT: ft.Colors.ON_PRIMARY if primary else MUTED,
            ft.ControlState.DISABLED: MUTED},
        bgcolor={ft.ControlState.DEFAULT: MINT, ft.ControlState.DISABLED: EDGE} if primary else None,
    )
    if primary:
        return ft.Button(label, style=style, elevation=0, on_click=on_click)
    return ft.TextButton(label, style=style, on_click=on_click)


def app_dialog(title, icon, fields, actions, *, width=460):
    return ft.AlertDialog(
        title=ft.Row([
            ft.Container(ft.Icon(icon, color=MINT, size=24), width=44, height=44,
                alignment=ft.Alignment.CENTER, bgcolor=ft.Colors.PRIMARY_CONTAINER, border_radius=12),
            ft.Text(title, size=22, color=TEXT, weight=ft.FontWeight.W_600, expand=True),
        ], spacing=12),
        content=ft.Column(fields, width=width, tight=True, spacing=18,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH),
        scrollable=True,
        actions=actions, actions_alignment=ft.MainAxisAlignment.END, actions_overflow_button_spacing=8,
        bgcolor=SURFACE, elevation=0,
        shape=ft.RoundedRectangleBorder(radius=20, side=ft.BorderSide(1, EDGE)),
        title_padding=ft.Padding.only(left=24, top=24, right=24, bottom=24),
        content_padding=ft.Padding.symmetric(horizontal=24),
        actions_padding=24, action_button_padding=0,
        inset_padding=ft.Padding.symmetric(horizontal=16, vertical=24),
    )


def info_hint(message):
    return ft.PopupMenuButton(
        content=ft.Container(ft.Icon(ft.Icons.INFO_OUTLINE, size=20, color=MUTED),
            width=44, height=44, alignment=ft.Alignment.CENTER),
        padding=0, bgcolor=EDGE, menu_position=ft.PopupMenuPosition.UNDER,
        shape=ft.RoundedRectangleBorder(radius=12),
        size_constraints=ft.BoxConstraints(min_width=280, max_width=320),
        items=[ft.PopupMenuItem(content=text(message, 13), padding=14)],
        tooltip=ft.Tooltip(
            # Hover still works in manual mode; taps open only the popup above.
            message=message, trigger_mode=ft.TooltipTriggerMode.MANUAL,
            mouse_cursor=ft.MouseCursor.CLICK, wait_duration=300,
            size_constraints=ft.BoxConstraints(max_width=320),
            margin=16, padding=14, bgcolor=EDGE,
            text_style=ft.TextStyle(size=13, color=TEXT),
        ),
    )


def with_info(control, message):
    if isinstance(control, ft.Switch) and isinstance(control.label, str):
        label, control.label = control.label, None
        control = ft.ListTile(leading=control, title=text(label),
            toggle_inputs=True, disabled=control.disabled, content_padding=0, horizontal_spacing=0)
    control.expand = True
    return ft.Row([control, info_hint(message)], spacing=8)


def bytes_text(value: int) -> str:
    for unit in ["Б", "КБ", "МБ", "ГБ", "ТБ"]:
        if value < 1000:
            return f"{value:.1f} {unit}" if unit != "Б" else f"{value} Б"
        value /= 1000
    return f"{value:.1f} ПБ"


class AppUI:
    def __init__(self, page, repository, manager, core, *, android=False):
        self.page, self.repo, self.manager, self.core = page, repository, manager, core
        self.android = android
        self.tab = 0
        self.search = ""
        self.filter = "all"
        self.stop = asyncio.Event()
        self.tasks = []
        self.busy_sources = set()
        self.active_profile = None
        self.connect_task = None
        self.disconnect_pending = False
        self.connection_lock = asyncio.Lock()
        self.settings_lock = asyncio.Lock()
        self.latency_task = None
        self.latency_key = None
        self.latency_results = {}
        self.latency_proxy_connected = False
        self.latency_method_label = text("", 11, MUTED)
        self.latency_value = text("—", 16, MUTED)
        self.bulk_task = None
        self.bulk_method = "tcp"
        self.bulk_active_method = None
        self.bulk_results = {}
        self.bulk_pending = set()
        self.bulk_total = 0
        self.bulk_session_status = None
        self.bulk_last_update = 0
        self.bulk_progress = text("", 12, MUTED)
        self.bulk_button = ft.Button("Измерить все", icon=ft.Icons.SPEED, on_click=self.measure_server_list)
        self.bulk_cancel = ft.TextButton("Отмена", on_click=self.cancel_server_measurement, visible=False)
        self.bulk_method_control = ft.Dropdown(label="Метод проверки", value="tcp",
            options=[ft.DropdownOption("tcp", "TCP/UDP"), ft.DropdownOption("icmp", "ICMP"),
                *([] if android else [ft.DropdownOption("proxy", "PROXY GET")])], on_select=self.change_bulk_method,
            col=6)
        self.closed = False
        self.import_pending = False
        self.import_busy = False
        self.startup_dialog = None
        self.body = ft.Container(expand=True)
        self.rendered_tab = None
        self.home_view = ft.Column(spacing=18)
        self.home_card = panel(ft.Column(spacing=12), padding=0)
        self.home_list = ft.Column(spacing=10)
        self.home_list_viewport = ft.Container(self.home_list)
        self.home_list_title = text("Серверы", 14, MUTED)
        self.home_list_title.expand = True
        self.home_bulk_progress = text("", 12, MUTED)
        self.home_latency_button = ft.IconButton(ft.Icons.SPEED,
            tooltip="Измерить TCP/UDP-задержку серверов списка", on_click=self.measure_home_servers)
        self.home_list_section = ft.ExpansionTile(
            title=ft.Row([self.home_list_title, self.home_latency_button], spacing=8),
            controls=[self.home_bulk_progress, self.home_list_viewport],
            expanded=False, maintain_state=True,
            on_change=self.home_expansion_changed,
            tile_padding=ft.Padding.symmetric(horizontal=20, vertical=8),
            controls_padding=ft.Padding.only(left=16, right=16, bottom=16),
            expanded_cross_axis_alignment=ft.CrossAxisAlignment.STRETCH,
            shape=ft.RoundedRectangleBorder(radius=20),
            collapsed_shape=ft.RoundedRectangleBorder(radius=20),
            text_color=TEXT, collapsed_text_color=TEXT,
            icon_color=MINT, collapsed_icon_color=MUTED,
        )
        self.sidebar = ft.Container(width=220, bgcolor=ft.Colors.SURFACE_CONTAINER_LOWEST, padding=24)
        self.bottom = ft.NavigationBar(destinations=[ft.NavigationBarDestination(icon=i, label="Главная" if n == "Подключение" else n) for n, i in NAV],
            selected_index=0, on_change=self.navigate, bgcolor=ft.Colors.SURFACE_CONTAINER_LOWEST)
        self.stat_up, self.stat_down, self.stat_time = text("0 Б", 24), text("0 Б", 24), text("00:00:00", 24)
        self.status_text = text("Отключено", 16, MUTED)
        self.mode_text = text("", 13, MUTED)
        self.core_text = text("", 12, MUTED)
        self.error_log_button = ft.TextButton("Открыть журнал ошибки", icon=ft.Icons.SUBJECT_ROUNDED,
            on_click=lambda e: self.open_tab(4), visible=False)
        self.connection_button = ft.IconButton(ft.Icons.SHIELD_OUTLINED, icon_size=72,
            icon_color=MUTED, disabled_color=MUTED, bgcolor=SURFACE, height=150, width=150,
            tooltip="Подключить", on_click=self.toggle_connection,
            style=ft.ButtonStyle(shape=ft.CircleBorder(), side=ft.BorderSide(1, EDGE), animation_duration=250))
        self.connection_progress = ft.ProgressRing(width=166, height=166, stroke_width=3,
            stroke_align=-1, stroke_cap=ft.StrokeCap.ROUND, padding=0,
            color=YELLOW, bgcolor=ft.Colors.TERTIARY_CONTAINER, visible=False)
        # Keep the button above the indicator so cancelling remains clickable.
        self.connection_visual = ft.Stack([self.connection_progress, self.connection_button],
            width=166, height=166, alignment=ft.Alignment.CENTER)
        self.state_hint = text("Добавьте подписку или отдельный сервер, чтобы начать.", 13, MUTED)
        self.latency_button = ft.TextButton("Измерить задержку", icon=ft.Icons.SPEED,
            on_click=self.measure_selected_latency, disabled=True)

    def start(self, *, initial_link=None, link_reader=None):
        page = self.page
        page.title = "Lunaris client"
        page.bgcolor, page.padding, page.spacing = BG, 0, 0
        configure_theme(page)
        if not self.android and not page.web:
            page.window.width, page.window.height = 1100, 790
            page.window.min_width, page.window.min_height = 390, 640
            page.window.prevent_close = True
            page.window.on_event = self.window_event
        page.on_disconnect = self.on_disconnect
        page.on_resize = self.resize
        # The Scaffold's navigation slot removes the top system inset from the
        # bar. Inside the body Column, Flutter's NavigationBar adds that inset
        # above its destinations, leaving a blank strip on edge-to-edge Android.
        page.add(ft.SafeArea(ft.Row([self.sidebar, self.body], expand=True, spacing=0), expand=True))
        self.render()
        self.resize()
        self.tasks = [asyncio.create_task(self.refresh_loop()), asyncio.create_task(self.manager.scheduler(self.stop)), asyncio.create_task(self.state_events())]
        if link_reader is not None:
            self.tasks.append(asyncio.create_task(self.import_link_loop(link_reader)))
        if initial_link is not None:
            self.confirm_import_link(initial_link)
        elif not self.repo.state.subscriptions:
            self.subscription_dialog(startup=True)

    async def import_link_loop(self, reader):
        while not self.stop.is_set():
            try:
                if not self.import_pending and not self.import_busy:
                    link = await reader()
                    if link is not None:
                        self.confirm_import_link(link)
                        if not self.android and not self.page.web:
                            self.page.window.minimized = False
                            self.page.window.visible = True
                            self.page.window.focused = True
                            self.page.update()
                            await self.page.window.to_front()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Native exceptions must never put a subscription token in logs.
                self.core.log.add("Не удалось обработать ссылку импорта.")
            await asyncio.sleep(0.5)

    def confirm_import_link(self, link):
        if self.startup_dialog is not None:
            self.startup_dialog.open = False
            self.startup_dialog = None
            self.page.update()

        def information(title, message):
            def dismissed(_):
                if self.import_pending is dialog:
                    self.import_pending = False
            def close(_):
                dialog.open = False
                dismissed(None)
                self.page.update()
            dialog = app_dialog(title, ft.Icons.LINK_ROUNDED, [text(message)],
                [dialog_button("Закрыть", on_click=close)])
            dialog.on_dismiss = dismissed
            self.import_pending = dialog
            self.page.show_dialog(dialog)

        try:
            url = subscription_url(link)
        except UserError as error:
            information("Импорт подписки", str(error))
            return
        if any(s.url == url for s in self.repo.state.subscriptions):
            information("Подписка уже добавлена", "Эта подписка уже есть в клиенте.")
            return
        source = dialog_field(label="Адрес подписки", value=url, read_only=True,
            password=True, can_reveal_password=True)
        note = text(f"Импортировать подписку с {urlsplit(url).hostname}?", 14)
        cancel = dialog_button("Отмена")
        submit = dialog_button("Импортировать", primary=True)

        def dismissed(_=None):
            if self.import_pending is dialog:
                self.import_pending = False
            source.value = ""

        def close(_=None):
            if self.import_pending is dialog:
                dialog.open = False
            dismissed()
            self.page.update()

        async def confirm(_):
            if submit.disabled or self.import_pending is not dialog:
                return
            self.import_busy = True
            submit.disabled = cancel.disabled = True
            note.value = "Загружаем серверы…"
            self.page.update()
            existing_ids = {s.id for s in self.repo.state.subscriptions}
            try:
                await self.manager.add("", url)
                close()
                self.open_tab(2)
            except Exception as error:
                if any(s.id not in existing_ids for s in self.repo.state.subscriptions):
                    close()
                    self.open_tab(2)
                    await self.notify_error(UserError("Подписка сохранена, но загрузка не удалась. Повторите обновление в её карточке."))
                else:
                    note.value = str(error) if isinstance(error, UserError) else "Не удалось сохранить подписку."
            finally:
                self.import_busy = False
                submit.disabled = cancel.disabled = False
                self.page.update()

        cancel.on_click, submit.on_click = close, confirm
        dialog = app_dialog("Импорт подписки", ft.Icons.LINK_ROUNDED, [note, source], [cancel, submit])
        dialog.modal = True
        dialog.on_dismiss = dismissed
        self.import_pending = dialog
        self.page.show_dialog(dialog)

    async def notify_error(self, error):
        message = str(error) if isinstance(error, UserError) else "Операция не выполнена. Проверьте настройки и защищённое хранилище."
        self.core.log.add(message)
        self.page.show_dialog(ft.SnackBar(text(message, color=ft.Colors.ON_ERROR_CONTAINER), bgcolor=ft.Colors.ERROR_CONTAINER))

    async def guarded(self, action):
        try:
            await action()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            await self.notify_error(error)
        self.render()

    def resize(self, _=None):
        narrow = (self.page.width or 1100) < 760
        self.sidebar.visible = not narrow
        self.bottom.visible = narrow
        self.page.navigation_bar = self.bottom if narrow else None
        self.body.padding = ft.Padding.only(left=20, top=28, right=20, bottom=20) if narrow else 36
        if not self.closed:
            self.page.update()

    def navigate(self, event):
        self.tab = event.control.selected_index
        self.render()

    def open_tab(self, tab):
        self.tab = tab
        self.render()

    def render(self):
        if self.closed:
            return
        self.sidebar.content = ft.Column([
            ft.Row([ft.Icon(ft.Icons.NORTH_EAST_ROUNDED, color=MINT, size=30), text("LUNARIS", 23, TEXT, ft.FontWeight.W_700)]),
            ft.Container(height=36),
            *[ft.Container(ft.Row([ft.Icon(icon, color=MINT if self.tab == i else MUTED, size=21), text(name, 14, MINT if self.tab == i else MUTED)], spacing=12),
                padding=14, border_radius=12, bgcolor=ft.Colors.PRIMARY_CONTAINER if self.tab == i else None, on_click=lambda e, n=i: self.open_tab(n)) for i, (name, icon) in enumerate(NAV)],
            ft.Container(expand=True), text(f"Lunaris client {APP_VERSION}", 12, MUTED), self.core_text,
        ], expand=True, spacing=10)
        self.bottom.selected_index = self.tab
        screens = [self.home, self.servers, self.subscriptions, self.settings, self.logs]
        # Keep the viewport mounted while refreshing the current screen: its
        # Flutter scroll controller owns the user's position in the server list.
        if self.body.content is None or self.rendered_tab != self.tab:
            self.body.content = ft.Column(expand=True, spacing=24, scroll=ft.ScrollMode.AUTO)
            self.rendered_tab = self.tab
        self.body.content.controls = [text(NAV[self.tab][0], 28, TEXT, ft.FontWeight.W_600), screens[self.tab]()]
        self.update_status()
        self.page.update()

    def selected(self):
        return next((p for p in self.repo.state.profiles if p.key == self.repo.state.selected), None)

    def connection_running(self):
        return self.disconnect_pending or self.core.status in {Status.CONNECTED, Status.CONNECTING, Status.DISCONNECTING} or (
            self.connect_task is not None and not self.connect_task.done())

    def home(self):
        self.home_card.content.controls = [self.home_server_list()]
        metrics = ft.ResponsiveRow([
            panel(ft.Column([ft.Row([ft.Icon(icon, size=18, color=MINT), text(label, 12, MUTED)]), control], spacing=12), col={"xs": 12, "sm": 4})
            for label, control, icon in [("Отправлено", self.stat_up, ft.Icons.ARROW_UPWARD), ("Получено", self.stat_down, ft.Icons.ARROW_DOWNWARD), ("Длительность", self.stat_time, ft.Icons.TIMER_OUTLINED)]
        ], spacing=12, run_spacing=12)
        self.home_view.controls = [
            panel(ft.Column([
                self.connection_visual, self.status_text, self.mode_text, self.state_hint, self.error_log_button,
                self.latency_button, self.latency_metrics(),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=18), alignment=ft.Alignment.CENTER),
            self.home_card, metrics,
        ]
        return self.home_view

    def home_profiles(self):
        selected = self.selected()
        return [p for p in self.repo.state.profiles if p.source_id == selected.source_id] if selected else []

    def home_server_list(self):
        selected = self.selected()
        source = next((s for s in self.repo.state.subscriptions if selected and s.id == selected.source_id), None)
        profiles = self.home_profiles()
        title = f"Серверы подписки «{source.name}»" if source else "Ручные серверы" if selected else "Серверы"
        rows = self.server_rows(profiles, allow_remove=False) if profiles else [
            text("Выберите сервер в разделе «Серверы».", 13, MUTED)]
        # Keep the list and its ancestors mounted across refreshes, with the
        # full list height handled by the page's outer scrollable column.
        self.home_list.controls = rows
        self.home_list_title.value = f"{title} · {len(profiles)}"
        return self.home_list_section

    def home_expansion_changed(self, event):
        self.home_list_section.expanded = event.data

    def update_status(self):
        label, color = STATUS[self.core.status]
        self.status_text.value, self.status_text.color = label, color
        self.mode_text.value = "Режим: TUN · Всё устройство" if self.android or self.repo.state.settings.mode == "tun" else "Режим: Системный прокси"
        session_core = self.core.session_core or self.repo.state.settings.core
        self.core_text.value = f"Mihomo {MIHOMO_VERSION}" if session_core == "mihomo" else f"sing-box {CORE_VERSION} / Xray"
        if session_core != self.repo.state.settings.core:
            self.core_text.value += " · автоматически"
        self.error_log_button.visible = bool(self.core.error)
        busy = self.core.status in {Status.CONNECTING, Status.DISCONNECTING}
        self.connection_progress.visible = busy and self.tab == 0
        self.connection_progress.semantics_label = label
        self.connection_button.disabled = self.core.status == Status.DISCONNECTING or (self.selected() is None and self.core.status not in {Status.CONNECTING, Status.CONNECTED})
        connected = self.core.status == Status.CONNECTED
        self.connection_button.icon_color = MINT if connected else YELLOW if busy else MUTED
        self.connection_button.disabled_color = self.connection_button.icon_color
        self.connection_button.bgcolor = ft.Colors.PRIMARY_CONTAINER if connected else ft.Colors.TERTIARY_CONTAINER if busy else SURFACE
        self.connection_button.style.side = ft.BorderSide(1, MINT if connected else YELLOW if busy else EDGE)
        self.connection_button.tooltip = "Отмена" if self.core.status == Status.CONNECTING else "Отключить" if connected else "Отключается…" if self.core.status == Status.DISCONNECTING else "Подключить"
        self.state_hint.value = self.core.error or ("" if busy or connected or self.selected() else "Добавьте подписку или отдельный сервер, чтобы начать.")
        self.state_hint.visible = bool(self.state_hint.value)
        measuring = self.latency_task is not None and not self.latency_task.done()
        starting = self.core.status != Status.CONNECTED and self.connect_task is not None and not self.connect_task.done()
        bulk_measuring = self.bulk_task is not None and not self.bulk_task.done()
        self.latency_button.disabled = measuring or bulk_measuring or busy or starting or self.disconnect_pending or self.selected() is None or (
            self.repo.state.settings.latency_method == "proxy" and not connected)
        self.latency_button.content = "Измеряем…" if measuring else "Измерить задержку"
        self.update_latency_metrics()
        self.bulk_button.disabled = bulk_measuring or measuring or busy or starting or self.disconnect_pending or not self.visible_profiles()
        self.bulk_button.content = "Измеряем…" if bulk_measuring else "Измерить все"
        self.bulk_cancel.visible = bulk_measuring
        self.bulk_method_control.disabled = bulk_measuring
        self.home_latency_button.disabled = measuring or busy or starting or self.disconnect_pending or not self.home_profiles()
        self.home_latency_button.icon = ft.Icons.STOP_CIRCLE_OUTLINED if bulk_measuring else ft.Icons.SPEED
        self.home_latency_button.tooltip = "Остановить измерение задержки" if bulk_measuring else "Измерить TCP/UDP-задержку серверов списка"
        self.home_bulk_progress.value = self.bulk_progress.value
        self.home_bulk_progress.visible = bool(self.home_bulk_progress.value)

    def update_latency_metrics(self):
        profile = self.active_profile if self.core.status == Status.CONNECTED and self.active_profile else self.selected()
        results = self.latency_results if profile and profile.key == self.latency_key else {}
        measuring = profile and profile.key == self.latency_key and self.latency_task is not None and not self.latency_task.done()
        method = self.repo.state.settings.latency_method
        self.latency_method_label.value = transport_label(profile) if method == "tcp" and profile else LATENCY_LABELS[method]
        result = results.get(method)
        value = result.label if result else "Измеряем…" if measuring else "—"
        if method == "proxy" and self.core.status != Status.CONNECTED:
            value, result = "Подключите VPN", None
        self.latency_value.value = value
        self.latency_value.color = MINT if result and result.milliseconds is not None else MUTED

    def latency_metrics(self):
        return ft.Column([self.latency_method_label, self.latency_value], spacing=6,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER)

    async def measure_selected_latency(self, _):
        async with self.connection_lock, self.settings_lock:
            profile = self.active_profile if self.core.status == Status.CONNECTED and self.active_profile else self.selected()
            starting = self.core.status != Status.CONNECTED and self.connect_task is not None and not self.connect_task.done()
            if self.closed or profile is None or self.disconnect_pending or starting or self.core.status in {Status.CONNECTING, Status.DISCONNECTING}:
                return
            if self.latency_task is not None and not self.latency_task.done():
                return
            if self.bulk_task is not None and not self.bulk_task.done():
                return
            method = self.repo.state.settings.latency_method
            if method == "proxy" and self.core.status != Status.CONNECTED:
                return
            self.latency_key, self.latency_results = profile.key, {}
            self.latency_proxy_connected = method == "proxy" and self.core.status == Status.CONNECTED
            task = asyncio.create_task(measure_latency(copy.deepcopy(profile), copy.deepcopy(self.repo.state.settings),
                proxy_connected=self.latency_proxy_connected))
            self.latency_task = task
            self.render()
        try:
            results = await task
            if self.latency_task is task:
                self.latency_results = results
        except asyncio.CancelledError:
            if asyncio.current_task().cancelling():
                raise
        except Exception:
            await self.notify_error(UserError("Не удалось измерить задержку. Повторите проверку."))
        finally:
            if self.latency_task is task:
                self.latency_task = None
                if self.tab == 0:
                    self.render()

    async def cancel_latency(self):
        await self.cancel_server_measurement()
        task, self.latency_task = self.latency_task, None
        self.latency_key, self.latency_results = None, {}
        self.latency_proxy_connected = False
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def toggle_connection(self, _):
        async def toggle():
            async with self.connection_lock:
                if self.closed or self.core.status == Status.DISCONNECTING:
                    return
                if self.connection_running():
                    await self.disconnect_current()
                else:
                    await self.start_selected()
        await self.guarded(toggle)

    async def cancel_connect(self):
        if self.connect_task and not self.connect_task.done():
            self.connect_task.cancel()
            await asyncio.gather(self.connect_task, return_exceptions=True)

    async def disconnect_current(self):
        await self.cancel_latency()
        await self.cancel_connect()
        self.disconnect_pending = True
        await self.core.disconnect()
        if self.core.status != Status.DISCONNECTED:
            raise UserError(self.core.error or "Не удалось завершить текущее подключение. Повторите отключение.")
        self.active_profile = None
        self.disconnect_pending = False

    async def start_selected(self):
        # Wait for an in-flight settings save before starting a new session.
        async with self.settings_lock:
            if self.closed:
                return
            profile = copy.deepcopy(self.selected())
            if profile:
                await self.cancel_latency()
                settings = copy.deepcopy(self.repo.state.settings)
                self.active_profile = profile
                self.connect_task = asyncio.create_task(self.guarded(lambda: self.core.connect(profile, settings)))

    async def select_server(self, key):
        async def select():
            async with self.connection_lock:
                if self.closed:
                    return
                reconnect = self.connection_running()
                if key == self.repo.state.selected:
                    # A previous stop may have failed after saving the new key.
                    # Allow retrying that server while the old session remains.
                    if not reconnect or not self.active_profile or key == self.active_profile.key:
                        return
                # Persist first: a failed selection must leave the current VPN running.
                await self.manager.select(key)
                await self.cancel_latency()
                if reconnect:
                    await self.disconnect_current()
                    await self.start_selected()
        await self.guarded(select)

    def servers(self):
        async def search(event):
            self.search = event.control.value or ""
            self.server_list.controls = self.server_rows()
            self.update_status()
            self.page.update()

        async def filter_changed(event):
            self.filter = event.control.value or "all"
            self.server_list.controls = self.server_rows()
            self.update_status()
            self.page.update()

        search_box = ft.TextField(hint_text="Поиск по названию и протоколу", value=self.search, prefix_icon=ft.Icons.SEARCH, on_change=search, col=12)
        if self.filter not in {"all", "manual", *[s.id for s in self.repo.state.subscriptions]}:
            self.filter = "all"
        filter_box = ft.Dropdown(value=self.filter, label="Источник", options=[ft.DropdownOption("all", "Все серверы"), ft.DropdownOption("manual", "Вручную"), *[ft.DropdownOption(s.id, s.name) for s in self.repo.state.subscriptions]], on_select=filter_changed, col=6)
        self.bulk_progress.visible = bool(self.bulk_progress.value)
        self.server_list = ft.Column(self.server_rows(), spacing=10)
        return ft.Column([
            ft.Row([
                text(f"{len(self.repo.state.profiles)} серверов", 14, MUTED),
                ft.Button("Импорт", icon=ft.Icons.ADD, on_click=self.import_dialog),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.ResponsiveRow([search_box, filter_box, self.bulk_method_control], spacing=12, run_spacing=12),
            ft.Row([self.bulk_button, self.bulk_cancel], wrap=True, spacing=12),
            self.bulk_progress,
            self.server_list,
        ], spacing=20)

    def visible_profiles(self):
        profiles = []
        for profile in self.repo.state.profiles:
            if self.search.casefold() not in f"{profile.name} {profile.protocol}".casefold():
                continue
            if self.filter == "manual" and profile.source_id is not None or self.filter not in {"all", "manual"} and profile.source_id != self.filter:
                continue
            profiles.append(profile)
        return profiles

    async def change_bulk_method(self, event):
        if self.bulk_task is None or self.bulk_task.done():
            self.bulk_method = event.control.value

    async def measure_server_list(self, _):
        await self.measure_profile_list(self.visible_profiles(), self.bulk_method)

    async def measure_home_servers(self, _):
        if self.bulk_task is not None and not self.bulk_task.done():
            await self.cancel_server_measurement()
        else:
            self.home_list_section.expanded = True
            await self.measure_profile_list(self.home_profiles(), "tcp")

    async def measure_profile_list(self, profiles, method):
        async with self.connection_lock, self.settings_lock:
            if self.closed or self.disconnect_pending or self.core.status in {Status.CONNECTING, Status.DISCONNECTING}:
                return
            if any(task is not None and not task.done() for task in (self.bulk_task, self.latency_task, self.connect_task)):
                return
            profiles = copy.deepcopy(profiles)
            if not profiles:
                return
            self.bulk_active_method = method
            self.bulk_total = len(profiles)
            self.bulk_pending = {profile.key for profile in profiles}
            self.bulk_session_status = self.core.status
            self.bulk_last_update = 0
            self.bulk_progress.value = f"Проверено: 0 из {self.bulk_total}"
            for profile in profiles:
                self.bulk_results.setdefault(profile.key, {}).pop(method, None)

            def completed(key, result):
                self.bulk_results.setdefault(key, {})[method] = result
                self.bulk_pending.discard(key)
                self.bulk_progress.value = f"Проверено: {self.bulk_total - len(self.bulk_pending)} из {self.bulk_total}"
                now = asyncio.get_running_loop().time()
                if self.tab in {0, 1} and not self.closed and now - self.bulk_last_update >= 0.2:
                    self.bulk_last_update = now
                    if self.tab == 0:
                        self.home_server_list()
                        self.home_bulk_progress.value = self.bulk_progress.value
                        self.home_bulk_progress.visible = True
                    else:
                        self.server_list.controls = self.server_rows()
                        self.bulk_progress.visible = True
                    self.page.update()

            task = asyncio.create_task(measure_profiles(profiles, copy.deepcopy(self.repo.state.settings), method,
                proxy_probe=getattr(self.core, "probe_profile", None), on_result=completed,
                concurrency=2 if method == "proxy" else 8))
            self.bulk_task = task
            self.render()
        try:
            await task
        except asyncio.CancelledError:
            if asyncio.current_task().cancelling():
                raise
        except Exception:
            await self.notify_error(UserError("Не удалось завершить проверку списка серверов."))
        finally:
            if self.bulk_task is task:
                self.bulk_task = None
                self.bulk_pending.clear()
                if self.tab in {0, 1}:
                    self.render()

    async def cancel_server_measurement(self, _=None):
        task, self.bulk_task = self.bulk_task, None
        if task is not None and not task.done():
            completed = self.bulk_total - len(self.bulk_pending)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            self.bulk_progress.value = f"Проверка отменена: {completed} из {self.bulk_total}"
        self.bulk_pending.clear()
        if task is not None and self.tab in {0, 1}:
            self.render()

    def server_rows(self, profiles=None, *, show_latency=True, allow_remove=True):
        rows = []
        for profile in self.visible_profiles() if profiles is None else profiles:
            source = next((s.name for s in self.repo.state.subscriptions if s.id == profile.source_id), "Вручную")
            async def select(_, key=profile.key):
                await self.select_server(key)

            async def remove(_, key=profile.key):
                await self.guarded(lambda: self.manager.remove_manual(key))

            details = [flag_text(profile.name, size=16, color=TEXT, weight=ft.FontWeight.W_500), text(f"{profile.protocol.upper()} · {source}", 12, MUTED)]
            results = self.bulk_results.get(profile.key, {}) if show_latency else {}
            labels = []
            for method, label in [("tcp", transport_label(profile)), ("icmp", "ICMP"), ("proxy", "PROXY GET")]:
                result = results.get(method)
                if show_latency and profile.key in self.bulk_pending and method == self.bulk_active_method:
                    labels.append(text(f"{label}: измеряем…", 12, MUTED))
                elif result is not None:
                    labels.append(text(f"{label}: {result.label}", 12, MINT if result.milliseconds is not None else MUTED))
            if labels:
                details.append(ft.Row(labels, wrap=True, spacing=16))
            row = [ft.Icon(ft.Icons.CHECK_CIRCLE if profile.key == self.repo.state.selected else ft.Icons.RADIO_BUTTON_UNCHECKED, color=MINT if profile.key == self.repo.state.selected else MUTED),
                ft.Column(details, expand=True, spacing=6)]
            if allow_remove and profile.source_id is None:
                row.append(ft.IconButton(ft.Icons.DELETE_OUTLINE, tooltip="Удалить ручной сервер", on_click=remove))
            rows.append(ft.Container(ft.Row(row, spacing=16), padding=18, bgcolor=SURFACE, border_radius=14, on_click=select,
                border=ft.Border.all(1, MINT if profile.key == self.repo.state.selected else EDGE)))
        return rows or [panel(ft.Column([ft.Icon(ft.Icons.DNS_OUTLINED, color=MUTED, size=36), text("Нет серверов по выбранному фильтру", 17), text("Добавьте подписку или импортируйте ссылку.", 13, MUTED)], spacing=12))]

    def import_dialog(self, _):
        field = dialog_field(label="Ссылка, список ссылок или локальный JSON", multiline=True,
            min_lines=4, max_lines=8, password=False, autofocus=True)
        result = text("Ссылки и пароли сохраняются в защищённом хранилище.", 12, MUTED)
        async def submit(_):
            try:
                report = await self.manager.import_manual(field.value or "")
                field.value = ""
                result.value = f"Импортировано: {len(report.profiles)}. Дубликаты: {report.duplicates}. Отклонено: {len(report.rejected)}."
                if report.rejected:
                    result.value += "\n" + "\n".join(f"Строка {r.line}: {r.reason}" for r in report.rejected[:20])
                self.render()
            except Exception as error:
                result.value = str(error) if isinstance(error, UserError) else "Не удалось импортировать серверы."
            self.page.update()
        dlg = app_dialog("Импорт серверов", ft.Icons.DNS_OUTLINED, [field, result],
            [dialog_button("Закрыть", on_click=lambda e: self.page.pop_dialog()),
                dialog_button("Импортировать", primary=True, on_click=submit)], width=500)
        self.page.show_dialog(dlg)

    def subscriptions(self):
        async def update_all(_):
            if self.busy_sources:
                return
            self.busy_sources.add("all")
            self.render()
            try:
                errors = await self.manager.update_all()
                if errors:
                    await self.notify_error(UserError(f"Не обновлено подписок: {len(errors)}. Причины показаны в карточках."))
            finally:
                self.busy_sources.discard("all")
                self.render()

        cards = []
        for sub in self.repo.state.subscriptions:
            count = sum(p.source_id == sub.id for p in self.repo.state.profiles)
            stamp = datetime.fromtimestamp(sub.last_success).strftime("%d.%m.%Y %H:%M") if sub.last_success else "ещё не обновлялась"
            info = sub.userinfo
            details = [text(sub.name, 20, TEXT, ft.FontWeight.W_600), text(f"{count} серверов · Обновление: {stamp}", 12, MUTED)]
            if info:
                used = info.get("upload", 0) + info.get("download", 0)
                if "upload" in info or "download" in info:
                    details.append(text(f"Использовано {bytes_text(used)}" + (f" из {bytes_text(info['total'])}" if info.get("total") else ""), 13))
                    if info.get("total"):
                        details.append(ft.ProgressBar(value=min(1, used / info["total"]), color=MINT, bgcolor=EDGE))
                if info.get("expire"):
                    try:
                        details.append(text("Срок действия: " + datetime.fromtimestamp(info["expire"]).strftime("%d.%m.%Y"), 12, MUTED))
                    except (ValueError, OSError, OverflowError):
                        pass
            if sub.error:
                details.append(text(sub.error, 13, ft.Colors.ERROR))
            if sub.rejected or sub.duplicates:
                details.append(text(f"Отклонено строк: {len(sub.rejected)} · Дубликатов: {sub.duplicates}", 12, YELLOW))
                details.extend(text(f"Строка {r['line']}: {r['reason']}", 11, MUTED) for r in sub.rejected[:10])

            async def update(_, source=sub.id):
                if source in self.busy_sources or "all" in self.busy_sources:
                    return
                self.busy_sources.add(source)
                self.render()
                try:
                    await self.guarded(lambda: self.manager.update(source))
                finally:
                    self.busy_sources.discard(source)
                    self.render()

            async def remove(_, source=sub.id):
                await self.guarded(lambda: self.manager.remove(source))

            details.append(ft.Row([ft.TextButton("Обновляется…" if sub.id in self.busy_sources or "all" in self.busy_sources else "Обновить", icon=ft.Icons.REFRESH, on_click=update, disabled=bool(self.busy_sources)),
                ft.TextButton("Удалить", icon=ft.Icons.DELETE_OUTLINE, on_click=remove)], wrap=True))
            cards.append(panel(ft.Column(details, spacing=12)))
        return ft.Column([
            ft.Row([
                ft.Button("Добавить подписку", icon=ft.Icons.ADD, on_click=self.subscription_dialog,
                    expand=True, style=ft.ButtonStyle(padding=ft.Padding.symmetric(horizontal=8, vertical=12))),
                ft.TextButton("Обновить все", icon=ft.Icons.SYNC, on_click=update_all, disabled=bool(self.busy_sources),
                    expand=True, style=ft.ButtonStyle(padding=ft.Padding.symmetric(horizontal=8, vertical=12))),
            ], spacing=8),
            *(cards or [panel(ft.Column([text("Здесь появятся ваши подписки", 20), text("Поддерживаются текстовые списки URI и Base64. URL скрыт в интерфейсе после добавления.", 13, MUTED)], spacing=12))]),
        ], spacing=18)

    def subscription_dialog(self, _=None, *, startup=False):
        name = dialog_field(label="Название (необязательно)", hint_text="Определится автоматически из подписки")
        url = dialog_field(label="HTTP/HTTPS URL", password=True, can_reveal_password=True, autofocus=True)
        note = text("HTTPS проверяется по умолчанию. URL может содержать секретный токен.", 12, MUTED)
        button = dialog_button("Добавить и загрузить", primary=True)
        async def submit(_):
            if button.disabled:
                return
            button.disabled = True
            existing_ids = {s.id for s in self.repo.state.subscriptions}
            note.value = "Загружаем серверы…"
            self.page.update()
            try:
                await self.manager.add(name.value or "", url.value or "")
                url.value = ""
                self.page.pop_dialog()
                self.render()
            except Exception as error:
                note.value = str(error) if isinstance(error, UserError) else "Не удалось сохранить подписку."
                url.value = ""
                if any(s.id not in existing_ids for s in self.repo.state.subscriptions):
                    self.page.pop_dialog()
                    await self.notify_error(UserError("Подписка сохранена, но загрузка не удалась. Повторите обновление в её карточке."))
                self.render()
            finally:
                button.disabled = False
                self.page.update()
        button.on_click = submit
        dialog = app_dialog("Добавьте подписку" if startup else "Новая подписка",
            ft.Icons.LINK_ROUNDED, [url, name, note],
            [dialog_button("Позже" if startup else "Закрыть", on_click=lambda e: self.page.pop_dialog()), button])
        if startup:
            self.startup_dialog = dialog
        self.page.show_dialog(dialog)

    async def change_latency_method(self, event):
        control = event.control
        method = control.value
        control.disabled = True
        self.page.update()
        try:
            async with self.settings_lock:
                await self.manager.patch_settings(latency_method=method)
                await self.cancel_latency()
        except Exception as error:
            await self.notify_error(error)
        finally:
            control.value = self.repo.state.settings.latency_method
            control.disabled = False
            self.update_status()
            self.page.update()

    def settings(self):
        s = self.repo.state.settings
        running = self.connection_running()
        mode = ft.Dropdown(label="Режим", value="tun" if self.android else s.mode, disabled=self.android or running,
            options=[ft.DropdownOption("proxy", "Системный прокси"), ft.DropdownOption("tun", "TUN · Всё устройство")])
        async def change_mode(event):
            control = event.control
            selected_mode = control.value
            control.disabled = True
            self.page.update()
            try:
                async with self.settings_lock:
                    if self.connection_running():
                        raise UserError("Отключите соединение перед сменой режима.")
                    await self.manager.save_connection_mode(selected_mode)
            except Exception as error:
                await self.notify_error(error)
            finally:
                control.value = "tun" if self.android else self.repo.state.settings.mode
                control.disabled = self.android or self.connection_running()
                self.update_status()
                self.page.update()
        mode.on_select = change_mode
        engine = ft.Dropdown(label="Ядро", value=s.core, disabled=running,
            options=[ft.DropdownOption("sing-box", "sing-box / Xray"), ft.DropdownOption("mihomo", "Clash (Mihomo)")])
        dns_kind = ft.Dropdown(label="DNS транспорт", value=s.dns_kind, options=[ft.DropdownOption("https", "HTTPS (DoH)"), ft.DropdownOption("tls", "TLS (DoT)"), ft.DropdownOption("udp", "UDP через VPN")])
        dns = ft.TextField(label="IP DNS-сервера", value=s.dns_server)
        tls_name = ft.TextField(label="TLS-имя DNS", value=s.dns_tls_name)
        bootstrap = ft.TextField(label="Bootstrap DNS (IP для адреса VPN-сервера)", value=s.bootstrap_dns)
        mixed = ft.TextField(label="Порт локального прокси", value=str(s.mixed_port))
        api = ft.TextField(label="Порт управления", value=str(s.api_port))
        minutes = ft.TextField(label="Обновление, минуты (0 — выключено)", value=str(s.update_minutes))
        startup = ft.Switch(label="Обновлять подписки при запуске", value=s.update_on_start)
        ipv6 = ft.Switch(label="Маршрутизировать IPv6", value=s.ipv6)
        bypass = ft.Switch(label="Сайты .рф, .su и .ru напрямую (в обход VPN)", value=s.bypass_russian_domains, disabled=running)
        probe = ft.TextField(label="HTTPS URL проверки соединения", value=s.probe_url)
        verify = ft.Switch(label="Проверять HTTPS при подключении", value=s.verify_connection)
        latency_method = ft.Dropdown(label="Метод измерения задержки", value=s.latency_method,
            options=[ft.DropdownOption(key, label) for key, label in LATENCY_LABELS.items()],
            on_select=self.change_latency_method)
        path = ft.TextField(label="Путь к sing-box.exe (пусто — встроенное ядро)", value=s.core_path, visible=not self.android)
        mihomo_path = ft.TextField(label="Путь к mihomo.exe (пусто — встроенное ядро)", value=s.mihomo_path, visible=not self.android)
        async def change_core(event):
            control = event.control
            selected_core = control.value
            control.disabled = True
            self.page.update()
            try:
                async with self.settings_lock:
                    if self.connection_running():
                        raise UserError("Отключите соединение перед сменой ядра.")
                    await self.manager.save_core(selected_core)
            except Exception as error:
                await self.notify_error(error)
            finally:
                control.value = self.repo.state.settings.core
                control.disabled = self.connection_running()
                self.update_status()
                self.page.update()
        engine.on_select = change_core
        def autosave(control, field, convert=lambda value: value):
            control.disabled = running

            async def change(event):
                raw = event.control.value
                async with self.settings_lock:
                    try:
                        if self.connection_running():
                            raise UserError("Отключите соединение перед изменением настроек.")
                        try:
                            value = convert(raw)
                            updated = copy.deepcopy(self.repo.state.settings)
                            setattr(updated, field, value)
                            updated.validate()
                        except (ValueError, UserError) as error:
                            # Keep incomplete input editable without saving invalid data.
                            if control.value == raw:
                                control.error_text = str(error) if isinstance(error, UserError) else "Введите целое число."
                            return
                        await self.manager.patch_settings(**{field: value})
                        if control.value == raw and hasattr(control, "error_text"):
                            control.error_text = None
                    except Exception as error:
                        if control.value == raw:
                            saved = getattr(self.repo.state.settings, field)
                            control.value = str(saved) if isinstance(control, ft.TextField) else saved
                            if hasattr(control, "error_text"):
                                control.error_text = None
                        await self.notify_error(error)
                    finally:
                        control.disabled = self.connection_running()
                        self.page.update()

            if isinstance(control, ft.Dropdown):
                control.on_select = change
            else:
                control.on_change = change

        for control, field in [(dns_kind, "dns_kind"), (startup, "update_on_start"),
                               (ipv6, "ipv6"), (bypass, "bypass_russian_domains"), (verify, "verify_connection")]:
            autosave(control, field)
        for control, field in [(mixed, "mixed_port"), (api, "api_port"), (minutes, "update_minutes")]:
            autosave(control, field, int)
        for control, field in [(dns, "dns_server"), (tls_name, "dns_tls_name"), (bootstrap, "bootstrap_dns"),
                               (probe, "probe_url"), (path, "core_path"), (mihomo_path, "mihomo_path")]:
            autosave(control, field, str.strip)

        def section(title, controls):
            return panel(ft.ExpansionTile(
                title=title, controls=[ft.Column(controls, spacing=16)],
                expanded=False, maintain_state=True,
                tile_padding=ft.Padding.symmetric(horizontal=24, vertical=8),
                # Leave room for the first field's floating label above its border.
                controls_padding=ft.Padding.only(left=24, top=12, right=24, bottom=24),
                expanded_cross_axis_alignment=ft.CrossAxisAlignment.STRETCH,
                shape=ft.RoundedRectangleBorder(radius=20),
                collapsed_shape=ft.RoundedRectangleBorder(radius=20),
                text_color=TEXT, collapsed_text_color=TEXT,
                icon_color=MINT, collapsed_icon_color=MUTED,
            ), padding=0)

        return ft.Column([
            section(with_info(text("Подключение", 19),
                "Настройки сохраняются автоматически после изменения. Некорректные значения не сохраняются.\n\n"
                + ("Mihomo использует существующие профили. Android VPN-служба продолжает работать после закрытия экрана." if self.android else "Mihomo использует существующие профили и поддерживает системный прокси и TUN.")
                + "\n\nTUN маршрутизирует трафик устройства и требует прав администратора в Windows. Системный прокси работает для приложений, использующих WinINET. После закрытия Windows UI соединение останавливается; на Android служба продолжает работу."), [
                mode, engine,
                ft.ResponsiveRow([ft.Container(mixed, col={"xs": 12, "sm": 6}), ft.Container(api, col={"xs": 12, "sm": 6})], spacing=12, run_spacing=12), ipv6,
                with_info(bypass, "Включает прямое подключение ко всем доменам и поддоменам этих зон. DNS остаётся через VPN. Изменения применятся при следующем подключении."), path, mihomo_path,
                with_info(verify, "Проверяет доступ к HTTPS-сайту через выбранный сервер перед статусом «Подключено». Если выключить, подключение продолжится после запуска ядра без подтверждения доступа к интернету. На Android также отключается проверка DNS сайта и повторная проверка при смене сети. Измерение задержки работает независимо."),
                with_info(latency_method, "На главной показан один результат. PROXY GET проверяет HTTPS через подключённый VPN; TCP/UDP — адрес и порт сервера (UDP для Hysteria 2, TCP для остальных); ICMP — адрес сервера."), probe]),
            section(with_info(text("DNS", 19), "DNS-запросы туннеля идут через сервер. В Windows TUN адрес VPN-сервера разрешается через Bootstrap DNS до включения туннеля; при переподключении адрес обновляется."), [dns_kind, dns, tls_name, bootstrap]),
            section(text("Подписки", 19), [startup, minutes]),
        ], spacing=18)

    def logs(self):
        return ft.Column([text("До 300 последних записей. URL, UUID, пароли и ключи скрываются. Журнал хранится только в памяти.", 13, MUTED),
            panel(ft.Column([text(line, 12, MUTED) for line in self.core.log.lines] or [text("Ошибок пока нет", 14, MUTED)], spacing=8))], spacing=16)

    async def state_events(self):
        async for _ in self.core.events():
            if self.closed:
                return
            if self.core.status != Status.CONNECTED and self.latency_proxy_connected:
                await self.cancel_latency()
            elif self.bulk_task is not None and self.core.status != self.bulk_session_status:
                await self.cancel_server_measurement()
            self.update_status()
            self.page.update()

    async def refresh_loop(self):
        while not self.stop.is_set():
            await asyncio.sleep(1)
            if self.closed:
                return
            try:
                stats = await self.core.get_stats()
                self.stat_up.value, self.stat_down.value = bytes_text(stats.upload), bytes_text(stats.download)
                self.stat_time.value = f"{stats.duration // 3600:02}:{stats.duration // 60 % 60:02}:{stats.duration % 60:02}"
                if self.manager.changed.is_set():
                    self.manager.changed.clear()
                    # Preserve text field focus and incomplete input during background updates.
                    if self.tab != 3:
                        self.render()
                elif self.tab in {0, 4}:
                    if self.tab == 4:
                        self.render()
                    else:
                        self.update_status()
                        self.page.update()
                elif self.tab == 1:
                    self.update_status()
                    self.page.update()
            except Exception as error:
                self.core.log.add(str(error) if isinstance(error, UserError) else "Не удалось обновить состояние адаптера.")

    async def shutdown(self):
        if self.closed:
            return
        self.closed = True
        self.stop.set()
        await self.cancel_latency()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        async with self.connection_lock:
            await self.cancel_connect()
            if not self.android:
                await self.core.disconnect()

    async def window_event(self, event):
        if event.type == ft.WindowEventType.CLOSE:
            await self.shutdown()
            await self.page.window.destroy()

    async def on_disconnect(self, _):
        await self.shutdown()
