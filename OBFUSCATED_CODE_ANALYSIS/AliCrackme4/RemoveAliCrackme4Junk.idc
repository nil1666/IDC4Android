//PoC for:
//remove junk code of AliCrackme4



#include <idc.idc>

static main(void)
{
	auto junk_array;
	
	auto search_count = 6;																	// <-modify
	auto search_pattern0 = "?? ?? 2D E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BD E8";
	auto search_pattern1 = "?? ?? 2D E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??BD E8";	
	auto search_pattern2 = "?? ?? 2D E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BD E8";	
	auto search_pattern3 = "?? ?? 2D E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BD E8";	
	auto search_pattern4 = "?? ?? 2D E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BD E8";	
	auto search_pattern5 = "?? ?? 2D E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BD E8";	

		
	auto i;
	auto j = 0;
	auto hit_counter = 0;
	auto search_pattern;
	auto search_pattern_len;
	
	auto r_code;

	auto cursor;

	auto module_ea;
	auto module_start;
	auto module_end;
	auto module_name;
	auto module_size;
	auto junk_code_len = 0;
	
	r_code = GetArrayId("foo");
	if (r_code != -1) {
		DeleteArray(r_code);
	}

	junk_array = CreateArray("foo");
	if(junk_array == -1)
	{
		Message("err0\n");
		return -1;
	}
	

	SetArrayString(junk_array, 0, search_pattern0);					// <-add more
	SetArrayString(junk_array, 1, search_pattern1);					// <-add more	
	SetArrayString(junk_array, 2, search_pattern2);					// <-add more	
	SetArrayString(junk_array, 3, search_pattern3);					// <-add more	
	SetArrayString(junk_array, 4, search_pattern4);					// <-add more	
	SetArrayString(junk_array, 5, search_pattern5);					// <-add more	
					
	//enumerate each module and find xxx
	for( module_ea = GetFirstModule();
		module_ea != BADADDR;
		module_ea = GetNextModule(module_ea)
		)
	
	{
		module_name = GetModuleName(module_ea);
		module_size = GetModuleSize(module_ea);
		
//		Message("-----> module name %s, base: 0x%x, size: 0x%x\n", module_name, module_ea, module_size);
		
		if(strstr(module_name, "mobisec.so") != -1)
		{
			module_start = module_ea;
			module_end = GetNextModule(module_ea);

			
			Message("seg start 0x%x\n", module_start);
			Message("seg end 0x%x\n", module_end);						
		}
		
		
	
	}
	
	
	
	for(i = 0; i < search_count; i ++)
	{
		j = 0;
		search_pattern = GetArrayElement(AR_STR, junk_array, i);
		search_pattern_len = ( strlen(search_pattern) + 1 ) / 3;
		Message("search pattern: %s. lengh: 0x%x\n", search_pattern, search_pattern_len);

		
		for(cursor = FindBinary(module_start, SEARCH_DOWN|SEARCH_REGEX, search_pattern);
			cursor != BADADDR;
			cursor = FindBinary(cursor, SEARCH_NEXT|SEARCH_DOWN|SEARCH_REGEX, search_pattern)
			)
		{
//			Message("%x\n", strlen(search_pattern));
			Message("0x%x hit pattern %s\n", cursor, search_pattern);
//			Message("cursor: 0x%x module end: 0x%x\n", cursor, module_end);
/*			
			if(cursor >= module_end)
			{
				Message("tag00\n");
				break;
			}	
			else
				Message("continue from 0x%x\n", cursor);	
	
*/			
			
			MakeUnknown(cursor, search_pattern_len, DOUNK_EXPAND+DOUNK_DELNAMES);
			MakeCode(cursor);
			MakeFunction(cursor, cursor + search_pattern_len);
//			MakeArray(cursor, search_pattern_len);
			
//			AddBpt(cursor);
//			DelBpt(cursor);
			r_code = HideArea(
				cursor, 
				cursor + search_pattern_len, 
				"junk_" + atoa(i) + "_" + atoa(j),
				"junk_" + atoa(i) + "_" + atoa(j) + "_start", 
				"junk_" + atoa(i) + "_" + atoa(j) + "_end",
				-1
				);

						
			SetHiddenArea(cursor, 0);
			
			j ++;	
			hit_counter ++;	
			junk_code_len = junk_code_len + search_pattern_len;
			
		}
	}
	
	Message("%d block collapsed, junk code len 0x%x.\n", hit_counter, junk_code_len);
}