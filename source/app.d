import std.stdio;
import std.digest.sha;
import std.digest : toHexString;
import ranonrat.cryptod;

void main()
{
	writeln("starting this shit");
	OpenSslKey encriptionKey = GenerateMLKemKey(TypeMLkem.ML_KEM_512);

	string mensaje = "hola mundo";
	ubyte[32] hash = sha256Of(mensaje);
	writeln("sha256 result: ", toHexString(hash));
}
