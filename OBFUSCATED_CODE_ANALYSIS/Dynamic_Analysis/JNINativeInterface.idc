// JNINativeInterface offset: 
// 0x415B3044 - 0x4150B000 = 0xA8044
// 0x4158A044 - 0x414E2000 = 0xA8044
//  in libdvm.so, fix for your own box(is this address stable?)
// The internal sturcture: [offset, method], method area is stripped from jni.h file
// AddBpt on offset, if it is hit, show method desp

//success SetArrayString(long id,long idx,string str);
//Persistent Data Storage in IDC

// done for my nexus4 is broken:)

#include <idc.idc>

static main(void)
{
	auto jni_file;
	auto module_ea;
	auto module_name;
	auto module_size;
	auto JNINativeInterface_ea;
	auto JNINativeInterface_offset = 0xA8044;			//JNINativeInterface offset in libdvm.so, fix for your own box	
	
	
	auto JNINativeInterface_array;
	auto method_desp;
	auto last_method_desp;
	auto h_file;
	
	auto is_JNINativeInterface = 0;
	
	auto method_ea;
	auto i = 0;
	
	auto r_code;
	
	jni_file = AskFile(0, "jni.h", "Choose jni.h file"); 

	if(jni_file == 0)
	{
		Message("err when locating jni file");
		return -1;
	}
	
	//enumerate each module and find xxx
	for( module_ea = GetFirstModule();
		module_ea != BADADDR;
		module_ea = GetNextModule(module_ea)
		)
	
	{
		module_name = GetModuleName(module_ea);
		module_size = GetModuleSize(module_ea);
		
		Message("-----> module name %s, base: 0x%x, size: 0x%x\n", module_name, module_ea, module_size);

		if(strstr(module_name, "libdvm.so") != -1)
		{
			JNINativeInterface_ea = module_ea + JNINativeInterface_offset;
			Message("JNINativeInterface_ea: 0x%x\n", JNINativeInterface_ea);
			break;								
		}	
	}
	
	JNINativeInterface_array = CreateArray("foo");
	
	h_file = fopen(jni_file, "r");
	i = 0;
	last_method_desp = "";
	while((method_desp = readstr(h_file)) != -1)
	{
		if(strstr(method_desp, "struct JNINativeInterface {")!= -1)
		{
//			Message("%s\n", method_desp);
			is_JNINativeInterface = 1;
			continue;
		}	
		if(is_JNINativeInterface == 0)
			continue;
		if(strstr(method_desp, "};")!= -1)
			break;	
		if(strstr(method_desp, ";") != -1)
		{
			last_method_desp = last_method_desp + method_desp;
			Message("method offset 0x%x, name %s\n", (Dword(JNINativeInterface_ea + i * 4) / 4) * 4, last_method_desp);

			SetArrayString(JNINativeInterface_array, (Dword(JNINativeInterface_ea + i * 4) / 4) * 4, last_method_desp);
			i ++;
			AddBpt((Dword(JNINativeInterface_ea + i * 4) / 4) * 4);
			last_method_desp = "";
		}
		else
		{
			last_method_desp = last_method_desp + trim(method_desp);
		}
	}
	
	for ( r_code = GetDebuggerEvent(WFNE_ANY|WFNE_CONT, -1); // resume
		r_code > 0;
		r_code = GetDebuggerEvent(WFNE_ANY|WFNE_CONT, -1) )
	{	
		if ( r_code <= 0 )
			return -1;
		
		r_code = GetEventEa();

		method_desp = GetArrayElement(AR_STR, JNINativeInterface_array, r_code);
		if(method_desp != 0)
		{
			Message("method: %s invoked.\n", method_desp);
		}
		
//		if(strstr(method_desp, "CallStaticObjectMethod") != 0)
//			break;
	}	
}