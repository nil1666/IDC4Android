//PoC for:
//ptrace(PTRACE_TRACEME, 0, NULL, NULL);
//fopen("/proc/getpid()/cmdline");


#include <idc.idc>

static main(void)
{

	auto cursor;
	auto cursor1;
	auto r_code;

	auto module_ea;
	auto module_name;
	auto module_size;
	
	auto ptrace_ea;
	auto ptrace_count = 0;
	
	auto fopen_ea;
	auto fopen_count = 0;	
	auto patch_info = "/proc/1/cmdline";
	auto r_str;
	auto r_str_tmp;
	auto r_byte_tmp;
	auto p_cnt;
	
	auto cur_module_name;
	auto last_module_name;
		
	//enumerate each module and find xxx
	for( module_ea = GetFirstModule();
		module_ea != BADADDR;
		module_ea = GetNextModule(module_ea)
		)
	
	{
		module_name = GetModuleName(module_ea);
		module_size = GetModuleSize(module_ea);
		
//		Message("-----> module name %s, base: 0x%x, size: 0x%x\n", module_name, module_ea, module_size);
		
		if(strstr(module_name, "libc.so") != -1)
		{
			ptrace_ea = module_ea + 0x24270;				//ptrace in libc.so, fix for your own box
			AddBpt(ptrace_ea);
			Message("****> ptrace located at 0x%x\n", ptrace_ea);	
			
			fopen_ea = module_ea + 0x14928;					//fopen in libc.so, fix for your own box
			AddBpt(fopen_ea);
			Message("****> fopen located at 0x%x\n", fopen_ea);						
		}
		
		
	
	}
	
	for ( r_code = GetDebuggerEvent(WFNE_ANY|WFNE_CONT, -1); // resume
		r_code > 0;
		r_code = GetDebuggerEvent(WFNE_ANY|WFNE_CONT, -1) )
	{	
		if ( r_code <= 0 )
			return -1;
		
		r_code = GetEventEa();
		if(r_code == ptrace_ea)
		{

//		#define PTRACE_TRACEME             0
			if(GetRegValue("R0") == 0)
			{			
/* failed to update register value, i don't know why -:)
				StepUntilRet();
				r_code = GetDebuggerEvent(WFNE_ANY, -1);
				if ( r_code <= 0 )
				{
					Message("err ptrace\n");
					return -1;
				}	
				r_code = GetEventEa();
				if(SetRegValue(0, "R0") != 1)
				{
					Message("err0\n");
					return -1;
				}
				ptrace_count ++;
				Message("ptrace hit, %d times\n", ptrace_count);
//				return -1;
*/
				last_module_name = SegName(r_code);
				while( 1 )
				{
					StepOver();

					r_code = GetDebuggerEvent(WFNE_ANY|WFNE_CONT, -1);
					if ( r_code <= 0 )
						return -1;		
					r_code = GetEventEa();
					cur_module_name = SegName(r_code);	
//					Message("%s, %x\n", last_module_name, r_code);
					if(last_module_name != cur_module_name)
					{
						if(SetRegValue(0, "R0") != 1)
						{
							Message("err0\n");
							return -1;
						}
						ptrace_count ++;
						Message("ptrace hit, %d times\n", ptrace_count);					
						break;
					}
//					last_module_name = cur_module_name;
				}
				
			}
		}
		
		if(r_code == fopen_ea)
		{

			p_cnt = GetProcessQty();
//			Message("%d\n", p_cnt);	
			for(cursor = 0; cursor < p_cnt; cursor ++)
			{
//				Message("%d\n", GetProcessPid(cursor));	
				r_code = GetRegValue("R0");
				r_str = GetString(r_code, -1, ASCSTR_C);
//				Message("opendest: %s", r_str);

				r_str_tmp = sprintf("/proc/%d/cmdline", GetProcessPid(cursor));
//				Message("%s, %s\n", r_str_tmp, r_str);

				if(r_str == r_str_tmp)
				{
					fopen_count ++;
					Message("fopen hit, %d times\n", fopen_count);
					// modify the memory
					for(cursor1 = 0; cursor1 < strlen(patch_info); cursor1 ++)
					{
						r_byte_tmp = patch_info[cursor1];
//						Message("%s, %d\n", r_byte_tmp, ord(r_byte_tmp));
						PatchByte(r_code + cursor1, ord(r_byte_tmp));
//						return -1;
					}
					PatchByte(r_code + cursor1, 0);
//					break;
//					return -1;
				}
			}	

		}						
	}

}