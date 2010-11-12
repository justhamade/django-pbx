
function add2template() {
  // find what is selected in the pull down
  template = document.getElementById('template')
  actions_xml = document.getElementById('actions_xml')
  switch(template.value){
  {% for items in templates.iteritems  %}
  case "{{ items.0 }}":
    actions_xml.value += '{{ items.1 }}\n'
    break
  {% endfor %}
  }
}
