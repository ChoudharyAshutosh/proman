package com.upgrad.proman.service.exception;

import java.io.PrintStream;
import java.io.PrintWriter;

public class ResourceNotFoundException extends Exception{
    public String code;
    public String errorMessage;

    public ResourceNotFoundException(String code, String errorMessage) {
        this.code = code;
        this.errorMessage = errorMessage;
    }
    @Override
    public void printStackTrace(PrintStream s){
        super.printStackTrace(s);
    }
    @Override
    public void printStackTrace(PrintWriter s){
        super.printStackTrace(s);
    }
    public String getCode() {
        return code;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
/*
    public ResourceNotFound() {
        super();
    }

    public ResourceNotFound(String message) {
        super(message);
    }*/
}
