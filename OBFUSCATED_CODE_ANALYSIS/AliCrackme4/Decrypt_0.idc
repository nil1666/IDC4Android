// the first section decrypt
// useless -:)

#include <idc.idc>

static main() {
	
	auto r_code;
	auto offset = 0x754E3F1C - 0x7514c000;
	auto ea;
	auto module_ea;
	auto module_name;
	auto module_size;

	
	for( module_ea = GetFirstModule();
		module_ea != BADADDR;
		module_ea = GetNextModule(module_ea)
		)
	
	{
		module_name = GetModuleName(module_ea);
		module_size = GetModuleSize(module_ea);
		
		Message("-----> module name %s, base: 0x%x, size: 0x%x\n", module_name, module_ea, module_size);
						
		if(strstr(module_name, "mobisec") != -1)
		{
			break;
		}
	}
	ea = module_ea + offset;	
	Message("0x%x\n", module_ea);
	Message("0x%x\n", offset);
	Message("0x%x\n", ea);	
	AddBpt(ea);
	
//	return;
	for ( r_code = GetDebuggerEvent(WFNE_ANY|WFNE_CONT, -1); // resume
		r_code > 0;
		r_code = GetDebuggerEvent(WFNE_ANY|WFNE_CONT, -1) )
	{	
		if ( r_code <= 0 )
			return -1;
		
		r_code = GetEventEa();
		if(r_code == ea)
		{
			if(GetRegValue("R4") == GetRegValue("R6"))
				break;
		}
	}
}		