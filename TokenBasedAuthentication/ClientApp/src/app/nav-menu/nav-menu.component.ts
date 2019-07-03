import { Component } from '@angular/core';
import { AuthenticationService } from '../Services/authentication.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-nav-menu',
  templateUrl: './nav-menu.component.html',
  styleUrls: ['./nav-menu.component.css']
})
export class NavMenuComponent {
  isExpanded = false;

  constructor(private authenticationService: AuthenticationService, private router: Router) { }

  collapse() {
    this.isExpanded = false;
  }

  logOut() {
    this.authenticationService.logout();
    this.router.navigate['/login'];
    return false;
  }
  toggle() {
    this.isExpanded = !this.isExpanded;
  }
}
