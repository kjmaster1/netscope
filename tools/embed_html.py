import sys

def embed(input_file, output_file, var_name):
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('#pragma once\n\n')
        f.write(f'static const char {var_name}[] =\n')
        
        for line in content.split('\n'):
            # Escape backslashes and quotes
            line = line.replace('\\', '\\\\')
            line = line.replace('"', '\\"')
            f.write(f'    "{line}\\n"\n')
        
        f.write(';\n')

if __name__ == '__main__':
    embed('dashboard/index.html',
          'include/dashboard_html.h',
          'DASHBOARD_HTML')