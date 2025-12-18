from PIL import Image
import os

# مسار المشروع
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

# مسار الأيقونات الصحيح
ICONS_DIR = os.path.join(PROJECT_DIR, "src", "icons")

# إنشاء المجلد إذا لم يكن موجود
os.makedirs(ICONS_DIR, exist_ok=True)

icons = [
    "device",
    "analysis",
    "network",
    "exploit",
    "connect",
    "refresh",
    "scan",
    "export"
]

colors = [
    "blue",
    "green",
    "orange",
    "red",
    "purple",
    "cyan",
    "magenta",
    "yellow"
]

for name, color in zip(icons, colors):
    img = Image.new("RGB", (32, 32), color)
    path = os.path.join(ICONS_DIR, f"{name}.png")
    img.save(path)
    print(f"[+] Created icon: {path}")
