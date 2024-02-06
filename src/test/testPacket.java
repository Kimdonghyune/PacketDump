package test;

public class testPacket {

	public static void main(String[] args) {
		localnetworkSearch ls = new localnetworkSearch();
		networkSearch ns = new networkSearch();
		ls.start();
		ns.start();
	}
}
