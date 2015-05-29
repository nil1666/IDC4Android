// check Debugger -> Debugger option -> suspend on library load/unload
// run this script until mobisec.so appear
// the SetReg fucked me for a whole day

#include <idc.idc>

static main() {
	
	auto module_ea, module_name, module_size;
	auto r_code;
	auto init_offset = 0x38d5e4;
	auto init_ea;
	
	RefreshDebuggerMemory();
	//enumerate each module and find xxx
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
			init_ea = module_ea + init_offset;
/*		
			MakeUnknown(
				GetSegmentAttr(init_ea, SEGATTR_START), 
				GetSegmentAttr(init_ea, SEGATTR_END) - GetSegmentAttr(init_ea, SEGATTR_START), 
				DOUNK_EXPAND+DOUNK_DELNAMES);

			return;
*/			
			SetReg(init_ea, "T", 0);			
			Message("GetReg 0x%x, value: %d\n", init_ea, GetReg(init_ea, "T"));
						
/*		
			Message("init 0x%x\n", init_ea);
			Message("seg start 0x%x\n", GetSegmentAttr(init_ea, SEGATTR_START));
			Message("seg end 0x%x\n", GetSegmentAttr(init_ea, SEGATTR_END));
			Message("seg align %d\n", GetSegmentAttr(init_ea, SEGATTR_ALIGN));
			Message("seg bitness %d\n", GetSegmentAttr(init_ea, SEGATTR_BITNESS));
			Message("seg flags %d\n", GetSegmentAttr(init_ea, SEGATTR_FLAGS));				
			Message("seg type %d\n", GetSegmentAttr(init_ea, SEGATTR_TYPE));
			Message("seg sel %d\n", GetSegmentAttr(init_ea, SEGATTR_SEL));
			return;
								
			SetSegAddressing(init_ea, 1);
			
			r_code = SetSegDefReg(init_ea, "T", 0);
			if(r_code != 1)
			{
				Message("err-1\n");
			}
		
			Message("0x%x\n", module_ea + 0x38d5e4);	
*/			

			if(MakeCode(init_ea) == 0)
			{
				Message("err1 0x%x\n", init_ea);	
			}
		
			Message("-----> module name %s, base: 0x%x, size: 0x%x\n", module_name, module_ea, module_size);
			AddBpt(init_ea);					
		}
		

	
	}
	RunTo(init_ea);	
	return;
}
