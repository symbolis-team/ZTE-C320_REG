# импортируем модуль коннекта к свитчу
from connect import Sw_telnet as device

# вспомогательные функции
from regular_expression import get_last_onu, replace_olt_with_onu

# импортируем конфиг из YAML файла
from config import get_config
conf = get_config()
# Вытягиваем переменные из YAML файла
ip = conf['sw']["ip"]
login = conf['sw']["login"]
passwd = conf['sw']["passwd"]



# получаем свободное место по указаному порту
def free_onu(port_name):
    last_onu = device(ip, 1, login, passwd, ["terminal length 0", "conf t", f"show running-config interface {port_name}"])
    res = get_last_onu(last_onu.get_result()) + 1
    return res




# регистрируем ону
def registr_onu(port_name, free_onu_id, sn_onu, speed_onu, vlan_name, vlan_id, comment_onu):
    port_onu_name = replace_olt_with_onu(port_name)
    device(ip, 1, login, passwd, [ "conf t", 
     f"interface {port_name}",
     f"onu {free_onu_id}  type F601 sn {sn_onu}", 
     f"onu {free_onu_id} profile line {speed_onu} remote {vlan_name}",
      "exit", 
     f"interface {port_onu_name}:{free_onu_id}",
     f"service-port 1 vport 1 user-vlan {vlan_id} vlan {vlan_id}",
     f"name {comment_onu}",
     f"description {comment_onu}",
      "end","wr"
     ])
    









