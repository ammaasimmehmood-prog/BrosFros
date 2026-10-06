with open('brosfros.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(', fg_color="transparent"', '')
content = content.replace('fg_color="transparent", ', '')
content = content.replace('fg_color="transparent"', 'fg_color="#2B2B2B"')

with open('brosfros.py', 'w', encoding='utf-8') as f:
    f.write(content)
