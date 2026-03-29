# ── Convert image file to base64 string ──
# $imagePath = "D:\0_Personal\idcard_front_v2.jpg"           # ← change this
# $imagePath = "D:\0_Personal\idcard_front.jpg"
# $imagePath = "D:\0_Personal\519a.jpg"
$imagePath = "D:\0_Personal\Bunlong-profile.jpg"
$bytes     = [System.IO.File]::ReadAllBytes($imagePath)
$base64    = [System.Convert]::ToBase64String($bytes)

# Copy to clipboard for pasting into Postman
$base64 | Set-Clipboard

Write-Host "✅ Base64 copied to clipboard! Length: $($base64.Length) characters"