
# импортируем регулярку
import re
def get_last_onu(lines):
    # Используем регулярное выражение для поиска всех номеров ONU
    matches = re.findall(r'onu (\d+) type', lines)
    # Выбираем последнее совпадение
    last_onu_number = matches[-1] if matches else None
    # Находим свободное место (последняя ону + 1)
    res = int(last_onu_number)
    return(res)


# замена olt на onu
def replace_olt_with_onu(input_string):
    return input_string.replace('olt', 'onu')








