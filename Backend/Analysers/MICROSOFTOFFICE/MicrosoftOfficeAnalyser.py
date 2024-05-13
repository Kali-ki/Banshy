from oletools import oleid, olevba

def analyse_microsoft_office_file(filename=None):

    is_it_malicious = False

    oid = oleid.OleID(filename=filename)

    indicators = oid.check()

    for i in indicators:
        
        if(i.id == 'encrypted'):
            if(i.value == True):
                is_it_malicious = True

        elif(i.id == 'vba' or i.id == 'xlm'):
            if(i.value != 'No'):
                if(i.risk == 'HIGH'):
                    is_it_malicious = True
                elif(i.risk == 'Medium'):
                    #is_it_malicious = True
                    vbaparser = olevba.VBA_Parser(filename=filename)
                    results = vbaparser.analyze_macros()
                    if(vbaparser.nb_autoexec > 0 or
                       vbaparser.nb_suspicious > 0 or
                       vbaparser.nb_iocs > 0 or
                       vbaparser.nb_hexstrings > 0 or
                       vbaparser.nb_base64strings > 0 or
                       vbaparser.nb_dridexstrings > 0 or
                       vbaparser.nb_vbastrings > 0):
                        is_it_malicious = True
                    vbaparser.close()
                    
        elif(i.id == 'ext_rels'):
            if(i.value > 0):
                if(i.risk == 'HIGH'):
                    is_it_malicious = True
                elif(i.risk == 'Medium'):
                    is_it_malicious = True

    return is_it_malicious
  
