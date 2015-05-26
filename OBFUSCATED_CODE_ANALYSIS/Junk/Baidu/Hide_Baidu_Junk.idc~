//PoC for:
//hide junk code for baidu


#include <idc.idc>

static main(void)
{
	auto junk_array;
	
	auto search_count = 1;								// <-modify
	auto search_pattern0 = "60 BE 00 C0 5A 00 8D BE 00 50 E5 FF 57 83 CD FF EB 10";							// <-add

	auto i;
	auto j = 0;
	auto hit_counter = 0;
	auto search_pattern;
	auto search_pattern_len;
	
	auto r_code;

	auto cursor;
	
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
	
	for(i = 0; i < search_count; i ++)
	{
		j = 0;
		search_pattern = GetArrayElement(AR_STR, junk_array, i);
		search_pattern_len = ( strlen(search_pattern) + 1 ) / 3;
		Message("search pattern: %s. lengh: 0x%x\n", search_pattern, search_pattern_len);

		
		for(cursor = FindBinary(0, SEARCH_DOWN|SEARCH_REGEX, search_pattern);
			cursor != BADADDR;
			cursor = FindBinary(cursor, SEARCH_NEXT|SEARCH_DOWN|SEARCH_REGEX, search_pattern)
			)
		{
			Message("%x\n", strlen(search_pattern));
			Message("0x%x hit pattern %s\n", cursor, search_pattern);
			
			
			MakeUnknown(cursor, search_pattern_len, DOUNK_EXPAND+DOUNK_DELNAMES);
			MakeByte(cursor);
			MakeArray(cursor, search_pattern_len);
			
			r_code = HideArea(
				cursor, 
				cursor + search_pattern_len, 
				"junk_" + atoa(i) + "_" + atoa(j),
				"junk_" + atoa(i) + "_" + atoa(j) + "_start", 
				"junk_" + atoa(i) + "_" + atoa(j) + "_end",
				-1
				);

			
			SetHiddenArea(cursor, 0 );
			j ++;	
			hit_counter ++;	
		}
	}
	
	Message("%d area collapsed\n", hit_counter);
}