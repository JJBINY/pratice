package appsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.TestConfiguration;

@TestConfiguration(proxyBeanMethods = false)
public class TestAppApplication {
	public static void main(String[] args) {
		SpringApplication.from(AppApplication::main).with(TestAppApplication.class).run(args);
	}
}
