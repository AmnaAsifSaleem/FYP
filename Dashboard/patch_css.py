with open('Dashboard/static/bootstrap-icons.css', 'r', encoding='utf-8') as f:
    content = f.read()
content = content.replace('./fonts/bootstrap-icons.woff2', '/static/fonts/bootstrap-icons.woff2')
content = content.replace('./fonts/bootstrap-icons.woff', '/static/fonts/bootstrap-icons.woff')
with open('Dashboard/static/bootstrap-icons.css', 'w', encoding='utf-8') as f:
    f.write(content)
print('Patched OK')
