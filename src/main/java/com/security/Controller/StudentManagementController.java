package com.security.Controller;

import com.security.Entity.Student;
import lombok.ToString;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/management/api/v1/students")
public class StudentManagementController {
    private static final List<Student> STUDENTS = Arrays.asList(

            new Student(1, "james bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anasmith")

    );

    @GetMapping
   @PreAuthorize("hasAnyRolle('ROLE_ADMIM,ROLE_ADMINTRAINEE')")
    public List<Student> getStudents() {

        return STUDENTS;
   }
@PostMapping
//@PreAuthorize("'hasAuthority'('student:write')")
    public void registerNewStudent(@RequestBody Student student) {
    System.out.println("registerNewStudent");
        System.out.println(student);
}
    @DeleteMapping(path = "studentId")
//    @PreAuthorize("'hasAuthority'('student:write')")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {

        System.out.println(studentId);
    }

    @PutMapping(path = "studentId")
//    @PreAuthorize("'hasAuthority'('student:write')")
    public void upDateStudent(@PathVariable("studentId")Integer studentId,@RequestBody Student student) {

        System.out.println(String.format("%s%s", studentId, student));

    }


}
