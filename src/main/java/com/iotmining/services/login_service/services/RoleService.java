package com.iotmining.services.login_service.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.iotmining.services.login_service.entity.Role;

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;

import java.util.List;

@Service
public class RoleService {

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    public void insertRolesInAllShards(List<String> roles) {
        insertRolesInShard(entityManagerFactory, roles);
    }

    private void insertRolesInShard(EntityManagerFactory entityManagerFactory, List<String> roles) {
        EntityManager entityManager = entityManagerFactory.createEntityManager();
        entityManager.getTransaction().begin();

        try {
            for (String roleName : roles) {
                if (entityManager.createQuery("SELECT r FROM Role r WHERE r.roleName  = :roleName", Role.class)
                        .setParameter("roleName", roleName)
                        .getResultList().isEmpty()) {
                    entityManager.persist(new Role(roleName));
                }
            }
            entityManager.getTransaction().commit();
        } catch (Exception e) {
            entityManager.getTransaction().rollback();
            throw e;
        } finally {
            entityManager.close();
        }
    }
}
