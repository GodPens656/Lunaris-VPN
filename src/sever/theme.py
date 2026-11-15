"""Semantic colors let Flutter follow device brightness without rebuilding the UI."""
import flet as ft

BG = ft.Colors.SURFACE
SURFACE = ft.Colors.SURFACE_CONTAINER_LOW
EDGE = ft.Colors.OUTLINE_VARIANT
TEXT = ft.Colors.ON_SURFACE
MUTED = ft.Colors.ON_SURFACE_VARIANT
MINT = ft.Colors.PRIMARY
YELLOW = ft.Colors.TERTIARY


def configure_theme(page):
    page.theme_mode = ft.ThemeMode.SYSTEM
    page.bgcolor = BG
    page.theme = ft.Theme(
        color_scheme_seed="#006B53", font_family="Segoe UI",
        color_scheme=ft.ColorScheme(
            primary="#006B53", on_primary="#FFFFFF",
            primary_container="#D3F5E7", on_primary_container="#103D30",
            surface="#F3F6FA", surface_container_low="#FFFFFF",
            surface_container_lowest="#EAF0F6", on_surface="#17243B",
            on_surface_variant="#52647A", outline="#708096", outline_variant="#D6DFEA",
            tertiary="#785600", tertiary_container="#FFF0C5", on_tertiary_container="#443100",
            error="#B3261E", error_container="#FCE5E3", on_error_container="#601410",
        ),
    )
    page.dark_theme = ft.Theme(
        color_scheme_seed="#76E8C3", font_family="Segoe UI",
        color_scheme=ft.ColorScheme(
            primary="#76E8C3", on_primary="#00382A",
            primary_container="#18332F", on_primary_container="#B6F5DE",
            surface="#0B111B", surface_container_low="#131D2B",
            surface_container_lowest="#0D1623", on_surface="#E8EEF5",
            on_surface_variant="#94A4B9", outline="#61748E", outline_variant="#253248",
            tertiary="#F3C871", tertiary_container="#332B1B", on_tertiary_container="#FFE2A5",
            error="#FFA6A6", error_container="#5F2932", on_error_container="#FFEDEA",
        ),
    )
