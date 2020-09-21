package com.example.signuplogin.domain.repository;

import com.example.signuplogin.model.Board;
import com.example.signuplogin.model.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<User, Long> {
}

