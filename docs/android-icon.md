# Android launcher icon

`src/assets/icon_android.png` is the Android-specific source selected by Flet.
The opaque gradient fills the adaptive layer; the white emblem stays inside
the central 66/108 safe circle. Android applies its own launcher mask.
`src/assets/icon.png` remains the Windows source.

Prepared with the built-in imagegen tool on 2026-10-18, using
`src/assets/icon.png` as the edit target. Final prompt:

> Edit target: the attached existing Lunaris VPN application icon. Produce a production Android adaptive icon source, square 1024x1024 pixels, flat full-bleed image, no text, no presentation, no border, NO rounded corners. Preserve the existing white crescent moon and five-point rounded star exactly, including their relative arrangement and silhouettes. Preserve the existing smooth pink-magenta-to-violet gradient background and extend it naturally across the entire canvas. ONLY CHANGE: scale down the whole white moon-and-star emblem together to fit entirely within a centered circle with diameter 58% of the square width (all white pixels must lie inside that circle). Center the complete emblem at image center. This extra background breathing space is essential because Android crops adaptive icons. The gradient must fill the entire square edge to edge, with NO inset tile, NO transparent margin, NO smaller square background behind the logo, NO shadow. Main emblem should be visibly smaller than input, with ample gradient-only margins. Do not change branding or add anything.

The resulting source is 1254×1254. Its measured white-emblem radius is 0.230
of the image width, within the safe radius 66/216 ≈ 0.306.
