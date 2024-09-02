// Name: callconv_quiz.c
// Compile: gcc -o callconv_quiz callconv_quiz.c
int __attribute__((cdecl)) sum(int a1, int a2, int a3){
	return a1 + a2 + a3;
}
void main(){
	int total = 0;
	total = sum(1, 2, 3);
}