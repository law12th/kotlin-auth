package com.ihm.auth.dtos

import java.time.LocalDate

class RegisterDTO {
    val firstName = ""
    val lastName = ""
    val username = ""
    val email = ""
    val dateOfBirth: LocalDate = LocalDate.now()
    val password = ""
}