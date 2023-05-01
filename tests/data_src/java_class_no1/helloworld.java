import java.util.*;

class HelloWorld {
    public static void main(String[] args) {
        Scanner obj = new Scanner(System.in);
        String name;
        System.out.println("Hello, enter your name!");
        name = obj.nextLine();
        System.out.println("Hello, World and hello, " + name);
    }
}
