package app.common;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Table;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class CleanUp {
    @PersistenceContext
    EntityManager entityManager;

    @Transactional
    public void all(){
        entityManager.getMetamodel().getEntities().stream()
                .map(et -> et.getJavaType().getAnnotation(Table.class).name())
                .forEach(table -> entityManager.createNativeQuery("TRUNCATE TABLE " + table).executeUpdate());
    }


}
