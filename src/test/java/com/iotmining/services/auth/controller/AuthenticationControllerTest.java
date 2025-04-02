//package com.iotmining.datafactory.auth.controller;
//
//import com.iotmining.datafactory.auth.dto.AuthResponseDTO;
//import com.iotmining.datafactory.auth.dto.UserCredentialDTO;
//import com.iotmining.datafactory.auth.datafactory.UserService;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.InjectMocks;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.junit.jupiter.MockitoExtension;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.test.web.servlet.MockMvc;
//
//import java.util.HashMap;
//import java.util.Map;
//
//import static org.junit.jupiter.api.Assertions.*;
//import static org.mockito.ArgumentMatchers.any;
//import static org.mockito.Mockito.when;
//
//@ExtendWith(MockitoExtension.class)
//public class AuthenticationControllerTest {
//    @Mock
//    private UserService userService;
//
//    @Autowired
//    private MockMvc mockMvc;
//
//    private UserCredentialDTO validateUser;
//    private UserCredentialDTO invalidLoginRequest;
////    private GenericResponseDTO<AuthResponseDTO> successResponse;
////    private GenericResponseDTO<?> failureResponse;
//    private AuthResponseDTO authResponseDetails;
//
//    @InjectMocks
//    private AuthenticationController authenticationController;
//
//    @BeforeEach
//    public void setup(){
//        validateUser = new UserCredentialDTO("user1", "Gndp8506@");
//        invalidLoginRequest = new UserCredentialDTO("invalidUser", "Gndp8506@");
////        authResponseDetails = new AuthResponseDTO("xyz", true);
////        successResponse = new GenericResponseDTO<>("Login successful", 200,  authResponseDetails);
////        failureResponse = new GenericResponseDTO<>("Invalid credentials", 401, null);
//
//    }
//
//    @Test
//    public void testLoginSuccess() throws Exception{
//        Map<String, Object> successResponse = new HashMap<>();
//        successResponse.put("statusCode", 200);
//        successResponse.put("message", "Login successful");
//        successResponse.put("token", "sample_jwt_token");
//
//        when(userService.verify(any(UserCredentialDTO.class))).thenReturn(successResponse);
//
//        // Call the login method
//        ResponseEntity<Map<String, Object>> responseEntity = authenticationController.login(validateUser);
//
//        // Assertions
//        assertNotNull(responseEntity);
//        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
//        assertEquals(200, responseEntity.getBody().get("statusCode"));
//        assertEquals("Login successful", responseEntity.getBody().get("message"));
//        assertTrue(responseEntity.getBody().containsKey("token"));
//
//    }
//
//    @Test
//    public void testLoginFailure() throws Exception{
//        Map<String, Object> failedResponse = new HashMap<>();
//        failedResponse.put("statusCode", 401);
//        failedResponse.put("message", "Invalid credentials");
//
//        when(userService.verify(any(UserCredentialDTO.class))).thenReturn(failedResponse);
//
//        // Call the login method
//        ResponseEntity<Map<String, Object>> responseEntity = authenticationController.login(invalidLoginRequest);
//
//        // Assertions
//        assertNotNull(responseEntity);
//        assertEquals(HttpStatus.UNAUTHORIZED, responseEntity.getStatusCode());
//        assertEquals(401, responseEntity.getBody().get("statusCode"));
//        assertEquals("Invalid credentials", responseEntity.getBody().get("message"));
//    }
//
//    @Test
//    public void login(){
//
//    }
//}
