from PIL import Image, ImageDraw

# Create simple colored icons
icons = ['device', 'analysis', 'network', 'exploit', 'connect', 'refresh', 'scan', 'export']
colors = ['blue', 'green', 'orange', 'red', 'purple', 'cyan', 'magenta', 'yellow']

for i, (name, color) in enumerate(zip(icons, colors)):
    img = Image.new('RGB', (32, 32), color)
    img.save(f'src/icons/{name}.png')
