// Name: callconv_quiz2
// Compile: gcc -o callconv_quiz2 callconv_quiz2.c
int sum(int a1, int a2, int a3){
	return a1 + a2 + a3;
}
void main(){
	int total = 0;
	total = sum(1, 2, 3);
}