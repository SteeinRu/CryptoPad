<?php

spl_autoload_register(function ($class_name) {
    include __DIR__.'/'.$class_name . '.php';
});