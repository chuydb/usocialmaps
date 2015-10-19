from HTMLParser import HTMLParser
from htmlentitydefs import name2codepoint

class CFEHTMLParser(HTMLParser):
    isInput = False
    isLabel = False
    isUser = False
    isPass = False
    isSubmit = False
    isBtnNvo = False
    isPaginacion = False
    isDdlRPU = False
    isInfoTable = False
    isTrTable = False
    isTdTable = False
    isNombreDesc = False
    isDivDatos = False
    isAddress = False
    tdCnt = 0
    isErrorMsg = False
    info_row = {'fecha_pago':'', 'fecha_vencimiento':'', 'kwh':'', 'monto_abonado':'', 'monto_total':''}
    data_gathered = {'btn_nuevo':False, 'rpu_values':[], 'data_info':[], 'error_msg':''}
    def handle_starttag(self, tag, attrs):
        if tag == "input":
            for attr in attrs:
                if attr[0] == 'name' and attr[1] == '__VIEWSTATE':
                    self.isInput = True
                if attr[0] == 'value' and self.isInput:
                    self.data_gathered['__VIEWSTATE'] = attr[1] 
                    self.isInput = False;
                if attr[0] == 'name' and self.isUser:
                    self.data_gathered['user_name'] = attr[1]
                    self.isUser = False
                if attr[0] == 'name' and self.isPass:
                    self.data_gathered['pass_name'] = attr[1]
                    self.isPass = False
                if attr[0] == 'type' and attr[1] == 'submit':
                    self.isSubmit = True
                if attr[0] == 'name' and self.isSubmit:
                    self.data_gathered['submit_name'] = attr[1]
                    self.isSubmit = False
                if attr[0] == 'name' and attr[1] == 'ctl00$PHContenidoPag$btnNuevo':
                    self.data_gathered['btn_nuevo']  = True
        if tag == "div":
            for attr in attrs:
                if attr[0] == 'id' and attr[1] == 'divDatos':
                    self.isDivDatos = True
        if tag == "p" and self.isDivDatos:
            self.isAddress = True
        if tag == "span":
            for attr in attrs:
                if attr[0] == 'id' and attr[1] == 'ctl00_PHContenidoPag_lblMensajeError':
                    self.data_gathered['btn_nuevo'] = False
                    self.isErrorMsg = True
                if attr[0] == 'id' and attr[1] == 'ctl00_PHContenidoPag_lblNombre':
                    self.isNombreDesc = True
        if tag == "label":
            self.isLabel = True
        if tag == "select":
            for attr in attrs:
                if attr[0] == 'class' and attr[1] == "paginacion":
                    self.isPaginacion = True
                if attr[0] == 'name' and self.isPaginacion:
                    self.data_gathered['paginacion_name'] = attr[1]
                if attr[0] == 'name' and attr[1] == 'ddlRPU':
                    self.isDdlRPU = True
        if tag == "option" and self.isDdlRPU:
            for attr in attrs:
                if attr[0] == 'value':
                    self.data_gathered['rpu_values'].append(attr[1])
        if tag == "table":
            for attr in attrs:
                if attr[0] == 'id' and attr[1] == 'ctl00_PHContenidoPag_gvHistorialPagos':
                    self.isInfoTable = True
                    break;
        if tag == "tr" and self.isInfoTable:
            self.isTrTable = True
        if tag == "td" and self.isInfoTable and self.isTrTable:
            self.isTdTable = True
    def handle_data(self, data):
        if self.isLabel and data == 'Nombre de usuario:':
            self.isUser = True
            self.isLabel = False
        elif self.isLabel and data[0:8] == 'Contrase':
            self.isPass = True
            self.isLabel = False 
        if self.isTdTable:
            if self.tdCnt == 0:
                self.data_gathered['data_info'].append({'fecha_pago':'', 'fecha_vencimiento':'', 'kwh':'', 'monto_abonado':'', 'monto_total':''})
                self.data_gathered['data_info'][-1]['fecha_pago'] = data
            elif self.tdCnt == 1:
                self.data_gathered['data_info'][-1]['fecha_vencimiento'] = data
            elif self.tdCnt == 2:
                self.data_gathered['data_info'][-1]['kwh'] = data
            elif self.tdCnt == 3:
                self.data_gathered['data_info'][-1]['monto_abonado'] = data
            elif self.tdCnt == 4:
                self.data_gathered['data_info'][-1]['monto_total'] = data
            self.tdCnt = self.tdCnt + 1
        if self.isNombreDesc:
            self.data_gathered['info_name'] = data
        if self.isAddress:
            self.data_gathered['data_info'].append({'address':data})
        if self.isErrorMsg:
            self.data_gathered['error_msg'] = data
    def handle_comment(self, data):
        pass
    def handle_entityref(self, name):
        c = unichr(name2codepoint[name])
    def handle_charref(self, name):
        if name.startswith('x'):
            c = unichr(int(name[1:], 16))
        else:
            c = unichr(int(name))
    def handle_decl(self, data):
        pass
    def handle_endtag(self, tag):
        if tag == "select":
            self.isDdlRPU = False
        if tag == "table" and self.isInfoTable:
            self.isInfoTable = False
        if tag == "tr" and self.isTrTable:
            self.tdCnt = 0
            self.isTrTable = False
        if tag == "tr" and self.isTdTable:
            self.isTdTable = False
        if tag == "span" and self.isNombreDesc:
            self.isNombreDesc = False
        if tag == "span" and self.isErrorMsg:
            self.isErrorMsg = False
        if tag == "p" and self.isAddress:
            self.isAddress = False
            self.isDivDatos = False