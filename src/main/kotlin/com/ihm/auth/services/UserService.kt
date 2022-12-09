package com.ihm.auth.services

import com.ihm.auth.dtos.RegisterDTO
import com.ihm.auth.dtos.UserDTO
import com.ihm.auth.entities.User
import com.ihm.auth.repositories.UserRepository
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service

@Service
class UserService(
    @Autowired
    private val userRepository: UserRepository
) {
    fun save(userRegistrationDetails: RegisterDTO): UserDTO {
        val user = User();

        user.firstName = userRegistrationDetails.firstName
        user.lastName = userRegistrationDetails.lastName
        user.username = userRegistrationDetails.username
        user.email = userRegistrationDetails.email
        user.dateOfBirth = userRegistrationDetails.dateOfBirth
        user.password = userRegistrationDetails.password

        userRepository.save(user)

        return user.let {
            UserDTO(
                it.id,
                it.firstName,
                it.lastName,
                it.username,
                it.email,
                it.dateOfBirth,
            )
        }
    }

    fun findByEmail(email: String): User? {
        return userRepository.findByEmail(email)
    }

    fun findById(id: Int): User? {
        return this.userRepository.findById(id).orElse(null)
    }
}