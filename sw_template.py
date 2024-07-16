from jinja2 import Template

def render_commands(template):
    jinja_template = Template(template)
    return jinja_template.render()

# Шаблон регистрации однопортовой ону
template_reg_onu = """
conf t
interface {port_name}
onu {free_onu_id}  type F601 sn {sn_onu}
onu {free_onu_id} profile line {speed_onu} remote {vlan_name}
exit
interface {port_onu_name}:{free_onu_id}
service-port 1 vport 1 user-vlan {vlan_id} vlan {vlan_id}
name {comment_onu}
description {comment_onu}
end
wr
"""

# Рендерим команды
onu_reg_commands = render_commands(template_reg_onu)