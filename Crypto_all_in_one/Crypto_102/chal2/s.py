print('ASCII:')
for i in range(128):
    try:
        bytes([i]).decode('ascii')
        print(f'{i} có thể decode')
    except:
        print(f'{i} không thể decode')