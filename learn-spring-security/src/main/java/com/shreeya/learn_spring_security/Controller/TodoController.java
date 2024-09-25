package com.shreeya.learn_spring_security.Controller;

import jakarta.annotation.security.RolesAllowed;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class  TodoController {
//    private Logger Logger = LoggerFactory.getLogger(getClass());

    public static final List<Todo> TODO_LIST =
            List.of(new Todo("shreeya", "Learn java"),
            new Todo("anisha", "learn microservices"));

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos(){
        return TODO_LIST;
    }


    @GetMapping("/users/{username}/todos")
    @PreAuthorize("hasRole('USER') and #username == authentication.name")
@PostAuthorize("returnObject.username=='shreeya'")
    @RolesAllowed({"ADMIN" , "USER"})
    @Secured({"ROLE_ADMIN", "ROLE_USER"})
    public Todo retrieveTodosByUsername(@PathVariable String username){
return TODO_LIST.get(0);
    }

    @PostMapping("/users/{username}/todos")
    public void createTodosForSpecificUser(@PathVariable String username , @RequestBody Todo todo){

//        Logger.info("creare {} for {}", todo, username);
    }


}

record Todo (String username, String description) {


}
