

typedef union	union_INT256	{
	char lineal[32];
	uint64_t numero[4];
}INT256;

void INT256_init(INT256 *n);
void INT256_increment(INT256 *n);
void INT256_decrement(INT256 *n);
void INT256_set(INT256 *n,char *data);

void INT256_init(INT256 *n)	{
	memset(n->lineal,0,32);
}

void INT256_increment(INT256 *n)	{
	n->numero[0]++;
	if(n->numero[0] == 0)	{
		n->numero[1]++;
		if(n->numero[1] == 0)	{
			n->numero[2]++;
			if(n->numero[2] == 0)	{
				n->numero[3]++;
			}
		}
	}
}

void INT256_decrement(INT256 *n)	{
	n->numero[0]--;
	if(n->numero[0] == 0xFFFFFFFFFFFFFFFF)	{
		n->numero[1]--;
		if(n->numero[1] == 0xFFFFFFFFFFFFFFFF)	{
			n->numero[2]--;
			if(n->numero[2] == 0xFFFFFFFFFFFFFFFF)	{
				n->numero[3]--;
			}
		}
	}
}



void INT256_set(INT256 *n,char *data)	{
	memcpy(n->lineal,data,32);
}