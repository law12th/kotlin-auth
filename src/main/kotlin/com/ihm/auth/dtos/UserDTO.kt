package com.ihm.auth.dtos

import java.time.LocalDate

data class UserDTO(
    var id: Int? = null,
    var firstName: String = "",
    var lastName: String = "",
    var username: String = "",
    var email: String = "",
    var dateOfBirth: LocalDate? = null,
    var password: String = "",
)
